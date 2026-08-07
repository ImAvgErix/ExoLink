use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use exo_domain::{AutomodAction, AutomodRule, AutomodRuleId, AutomodTrigger, GuildId, UserId};
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::char::is_combining_mark;

const MAX_PATTERN_BYTES: usize = 4_096;
const MAX_PATTERNS: usize = 32;
const MAX_REPEAT_HISTORY: usize = 20;
const POW_LIFETIME_MINUTES: i64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOfWorkChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOfWorkSolution {
    pub challenge: String,
    pub nonce: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProofOfWorkError {
    #[error("the proof-of-work challenge is invalid or expired")]
    InvalidChallenge,
    #[error("the proof-of-work solution is invalid")]
    InvalidSolution,
    #[error("proof-of-work generation failed")]
    Randomness,
    #[error("the proof-of-work search exhausted the nonce space")]
    Exhausted,
}

#[derive(Clone)]
pub struct ProofOfWorkManager {
    inner: Arc<Mutex<ProofOfWorkState>>,
    baseline_difficulty: u8,
    maximum_difficulty: u8,
}

#[derive(Default)]
struct ProofOfWorkState {
    challenges: HashMap<[u8; 32], PendingChallenge>,
    registrations: HashMap<String, VecDeque<DateTime<Utc>>>,
}

struct PendingChallenge {
    client_key: String,
    difficulty: u8,
    expires_at: DateTime<Utc>,
}

impl ProofOfWorkManager {
    /// Creates an adaptive challenge manager.
    ///
    /// # Panics
    ///
    /// Panics when the baseline exceeds the maximum or the maximum exceeds
    /// the supported 32-bit work factor.
    #[must_use]
    pub fn new(baseline_difficulty: u8, maximum_difficulty: u8) -> Self {
        assert!(baseline_difficulty <= maximum_difficulty);
        assert!(maximum_difficulty <= 32);
        Self {
            inner: Arc::new(Mutex::new(ProofOfWorkState::default())),
            baseline_difficulty,
            maximum_difficulty,
        }
    }

    /// Issues one IP/client-bound challenge.
    ///
    /// # Errors
    ///
    /// Returns [`ProofOfWorkError::Randomness`] if the operating system cannot
    /// provide secure random challenge bytes.
    pub fn issue(
        &self,
        client_key: impl Into<String>,
    ) -> Result<ProofOfWorkChallenge, ProofOfWorkError> {
        let client_key = client_key.into();
        let now = Utc::now();
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_pow_state(&mut state, now);
        let recent = state
            .registrations
            .get(&client_key)
            .map_or(0, VecDeque::len);
        let pressure = u8::try_from(recent.saturating_sub(2) / 2).unwrap_or(u8::MAX);
        let difficulty = self
            .baseline_difficulty
            .saturating_add(pressure.saturating_mul(2))
            .min(self.maximum_difficulty);
        let mut challenge = [0_u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| ProofOfWorkError::Randomness)?;
        let expires_at = now + TimeDelta::minutes(POW_LIFETIME_MINUTES);
        state.challenges.insert(
            challenge,
            PendingChallenge {
                client_key,
                difficulty,
                expires_at,
            },
        );
        Ok(ProofOfWorkChallenge {
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            difficulty,
            expires_at,
        })
    }

    /// Consumes and verifies a solution against its original client binding.
    ///
    /// # Errors
    ///
    /// Returns an invalid-challenge or invalid-solution error when the
    /// challenge is missing, expired, reused, bound to another client, or the
    /// submitted nonce does not satisfy its work factor.
    pub fn verify(
        &self,
        client_key: &str,
        solution: &ProofOfWorkSolution,
    ) -> Result<(), ProofOfWorkError> {
        let challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&solution.challenge)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(ProofOfWorkError::InvalidChallenge)?;
        let now = Utc::now();
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_pow_state(&mut state, now);
        let pending = state
            .challenges
            .remove(&challenge)
            .ok_or(ProofOfWorkError::InvalidChallenge)?;
        if pending.client_key != client_key || pending.expires_at <= now {
            return Err(ProofOfWorkError::InvalidChallenge);
        }
        if !valid_proof(&challenge, solution.nonce, pending.difficulty) {
            return Err(ProofOfWorkError::InvalidSolution);
        }
        state
            .registrations
            .entry(client_key.to_owned())
            .or_default()
            .push_back(now);
        Ok(())
    }
}

fn prune_pow_state(state: &mut ProofOfWorkState, now: DateTime<Utc>) {
    state
        .challenges
        .retain(|_, challenge| challenge.expires_at > now);
    let cutoff = now - TimeDelta::hours(1);
    state.registrations.retain(|_, registrations| {
        while registrations.front().is_some_and(|value| *value < cutoff) {
            registrations.pop_front();
        }
        !registrations.is_empty()
    });
}

#[must_use]
pub fn valid_proof(challenge: &[u8; 32], nonce: u64, difficulty: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce.to_le_bytes());
    has_leading_zero_bits(&hasher.finalize(), difficulty)
}

/// Finds a nonce satisfying a server challenge.
///
/// # Errors
///
/// Returns an invalid-challenge error for malformed challenge bytes or
/// [`ProofOfWorkError::Exhausted`] if no nonce can satisfy the challenge.
pub fn solve_proof_of_work(
    challenge: &ProofOfWorkChallenge,
) -> Result<ProofOfWorkSolution, ProofOfWorkError> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(ProofOfWorkError::InvalidChallenge)?;
    for nonce in 0..=u64::MAX {
        if valid_proof(&bytes, nonce, challenge.difficulty) {
            return Ok(ProofOfWorkSolution {
                challenge: challenge.challenge.clone(),
                nonce,
            });
        }
    }
    Err(ProofOfWorkError::Exhausted)
}

fn has_leading_zero_bits(hash: &[u8], difficulty: u8) -> bool {
    let full_bytes = usize::from(difficulty / 8);
    let remaining_bits = difficulty % 8;
    if hash
        .get(..full_bytes)
        .is_none_or(|prefix| prefix.iter().any(|byte| *byte != 0))
    {
        return false;
    }
    remaining_bits == 0
        || hash
            .get(full_bytes)
            .is_some_and(|byte| byte.leading_zeros() >= u32::from(remaining_bits))
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    pub limit: u32,
    pub period: Duration,
}

impl RateLimit {
    #[must_use]
    pub const fn new(limit: u32, period: Duration) -> Self {
        assert!(limit > 0);
        Self { limit, period }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub retry_after: Duration,
    pub reset_after: Duration,
}

#[derive(Clone, Default)]
pub struct GcraLimiter {
    arrivals: Arc<Mutex<HashMap<String, Instant>>>,
}

impl GcraLimiter {
    #[must_use]
    pub fn check(&self, key: &str, policy: RateLimit) -> RateLimitDecision {
        let now = Instant::now();
        let interval = duration_div(policy.period, policy.limit);
        let tolerance = duration_mul(interval, policy.limit.saturating_sub(1));
        let mut arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if arrivals.len() > 10_000 {
            // A bucket is fully recovered once its theoretical arrival is no
            // longer in the future. Keeping older entries based on whichever
            // policy happened to trigger pruning lets stale, mixed-policy keys
            // retain memory for as long as 24 hours.
            arrivals.retain(|_, arrival| *arrival > now);
        }
        let theoretical = arrivals.get(key).copied().unwrap_or(now);
        let allow_at = theoretical.checked_sub(tolerance).unwrap_or(now);
        if now < allow_at {
            return RateLimitDecision {
                allowed: false,
                limit: policy.limit,
                remaining: 0,
                retry_after: allow_at.duration_since(now),
                reset_after: theoretical.duration_since(now),
            };
        }
        let next = theoretical.max(now) + interval;
        arrivals.insert(key.to_owned(), next);
        let debt = next.saturating_duration_since(now);
        let used = duration_ceil_div(debt, interval).min(policy.limit);
        RateLimitDecision {
            allowed: true,
            limit: policy.limit,
            remaining: policy.limit.saturating_sub(used),
            retry_after: Duration::ZERO,
            reset_after: debt,
        }
    }
}

fn duration_div(duration: Duration, divisor: u32) -> Duration {
    Duration::from_nanos(
        u64::try_from(duration.as_nanos() / u128::from(divisor))
            .unwrap_or(u64::MAX)
            .max(1),
    )
}

fn duration_mul(duration: Duration, multiplier: u32) -> Duration {
    duration.saturating_mul(multiplier)
}

fn duration_ceil_div(numerator: Duration, denominator: Duration) -> u32 {
    let numerator = numerator.as_nanos();
    let denominator = denominator.as_nanos().max(1);
    u32::try_from(numerator.div_ceil(denominator)).unwrap_or(u32::MAX)
}

#[derive(Clone, Debug)]
pub struct AutomodContext<'a> {
    pub guild_id: GuildId,
    pub author_id: UserId,
    pub content: &'a str,
    pub account_created_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomodMatch {
    pub rule_id: AutomodRuleId,
    pub rule_name: String,
    pub action: AutomodAction,
    pub duration_seconds: Option<u32>,
    pub explanation: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AutomodError {
    #[error("automod rule names must contain 1–64 characters")]
    InvalidName,
    #[error("automod explanations must contain 1–256 characters")]
    InvalidExplanation,
    #[error("automod patterns must contain 1–32 entries and at most 4096 bytes")]
    InvalidPatterns,
    #[error("automod threshold is outside the supported range")]
    InvalidThreshold,
    #[error("automod timeout and ban actions require a duration of 60 seconds to 28 days")]
    InvalidDuration,
    #[error("automod regular expression is invalid: {0}")]
    InvalidRegex(String),
}

pub struct AutomodEngine {
    rules: Vec<CompiledRule>,
    repeats: Mutex<HashMap<(GuildId, UserId), VecDeque<RepeatEntry>>>,
}

struct RepeatEntry {
    hash: [u8; 32],
    created_at: DateTime<Utc>,
}

struct CompiledRule {
    rule: AutomodRule,
    matcher: CompiledMatcher,
}

enum CompiledMatcher {
    Keyword(AhoCorasick),
    Regex(RegexSet),
    InviteLink(Regex),
    MassMention(u16),
    RepeatedContent {
        threshold: u8,
        window_seconds: u16,
    },
    NewAccountLink {
        max_account_age_days: u16,
        link: Regex,
    },
    Zalgo(u16),
}

impl AutomodEngine {
    /// Validates and compiles enabled rules into bounded matchers.
    ///
    /// # Errors
    ///
    /// Returns [`AutomodError`] when any enabled rule has invalid limits,
    /// patterns, action parameters, or metadata.
    pub fn compile(rules: &[AutomodRule]) -> Result<Self, AutomodError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules.iter().filter(|rule| rule.enabled) {
            validate_rule(rule)?;
            compiled.push(CompiledRule {
                rule: rule.clone(),
                matcher: compile_matcher(&rule.trigger)?,
            });
        }
        compiled.sort_by_key(|rule| action_priority(rule.rule.action));
        Ok(Self {
            rules: compiled,
            repeats: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn evaluate(&self, context: &AutomodContext<'_>) -> Option<AutomodMatch> {
        let normalized = context.content.to_lowercase();
        let content_hash: [u8; 32] = Sha256::digest(normalized.as_bytes()).into();
        let mut repeats = self
            .repeats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let history = repeats
            .entry((context.guild_id, context.author_id))
            .or_default();
        history.retain(|entry| entry.created_at > context.now - TimeDelta::minutes(10));
        let matched = self.rules.iter().find(|compiled| {
            matcher_matches(
                &compiled.matcher,
                context,
                &normalized,
                &content_hash,
                history,
            )
        });
        history.push_back(RepeatEntry {
            hash: content_hash,
            created_at: context.now,
        });
        while history.len() > MAX_REPEAT_HISTORY {
            history.pop_front();
        }
        matched.map(|compiled| AutomodMatch {
            rule_id: compiled.rule.id,
            rule_name: compiled.rule.name.clone(),
            action: compiled.rule.action,
            duration_seconds: compiled.rule.duration_seconds,
            explanation: compiled.rule.explanation.clone(),
        })
    }
}

/// Validates one rule using the same limits as compilation.
///
/// # Errors
///
/// Returns [`AutomodError`] when metadata, limits, patterns, or action
/// parameters are invalid.
pub fn validate_rule(rule: &AutomodRule) -> Result<(), AutomodError> {
    let name_length = rule.name.trim().chars().count();
    if !(1..=64).contains(&name_length) {
        return Err(AutomodError::InvalidName);
    }
    let explanation_length = rule.explanation.trim().chars().count();
    if !(1..=256).contains(&explanation_length) {
        return Err(AutomodError::InvalidExplanation);
    }
    match rule.action {
        AutomodAction::Timeout | AutomodAction::Ban => {
            if !rule
                .duration_seconds
                .is_some_and(|seconds| (60..=2_419_200).contains(&seconds))
            {
                return Err(AutomodError::InvalidDuration);
            }
        }
        AutomodAction::Flag | AutomodAction::Block | AutomodAction::Kick => {
            if rule.duration_seconds.is_some() {
                return Err(AutomodError::InvalidDuration);
            }
        }
    }
    compile_matcher(&rule.trigger).map(|_| ())
}

fn compile_matcher(trigger: &AutomodTrigger) -> Result<CompiledMatcher, AutomodError> {
    match trigger {
        AutomodTrigger::Keyword { terms } => {
            validate_patterns(terms)?;
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(terms)
                .map(CompiledMatcher::Keyword)
                .map_err(|error| AutomodError::InvalidRegex(error.to_string()))
        }
        AutomodTrigger::Regex { patterns } => {
            validate_patterns(patterns)?;
            RegexSetBuilder::new(patterns)
                .size_limit(256 * 1024)
                .build()
                .map(CompiledMatcher::Regex)
                .map_err(|error| AutomodError::InvalidRegex(error.to_string()))
        }
        AutomodTrigger::InviteLink => Ok(CompiledMatcher::InviteLink(invite_regex()?)),
        AutomodTrigger::MassMention { limit } if (1..=100).contains(limit) => {
            Ok(CompiledMatcher::MassMention(*limit))
        }
        AutomodTrigger::RepeatedContent {
            threshold,
            window_seconds,
        } if (2..=10).contains(threshold) && (5..=600).contains(window_seconds) => {
            Ok(CompiledMatcher::RepeatedContent {
                threshold: *threshold,
                window_seconds: *window_seconds,
            })
        }
        AutomodTrigger::NewAccountLink {
            max_account_age_days,
        } if (1..=90).contains(max_account_age_days) => Ok(CompiledMatcher::NewAccountLink {
            max_account_age_days: *max_account_age_days,
            link: link_regex()?,
        }),
        AutomodTrigger::Zalgo {
            combining_mark_limit,
        } if (4..=1_000).contains(combining_mark_limit) => {
            Ok(CompiledMatcher::Zalgo(*combining_mark_limit))
        }
        _ => Err(AutomodError::InvalidThreshold),
    }
}

fn validate_patterns(patterns: &[String]) -> Result<(), AutomodError> {
    let bytes = patterns.iter().map(String::len).sum::<usize>();
    if patterns.is_empty()
        || patterns.len() > MAX_PATTERNS
        || bytes > MAX_PATTERN_BYTES
        || patterns.iter().any(|pattern| pattern.trim().is_empty())
    {
        return Err(AutomodError::InvalidPatterns);
    }
    Ok(())
}

fn invite_regex() -> Result<Regex, AutomodError> {
    Regex::new(
        r"(?i)(?:discord(?:app)?\.com/invite|discord\.gg|t\.me/joinchat|chat\.whatsapp\.com)/?[A-Za-z0-9_-]+",
    )
    .map_err(|error| AutomodError::InvalidRegex(error.to_string()))
}

fn link_regex() -> Result<Regex, AutomodError> {
    Regex::new(r"(?i)\b(?:https?://|www\.)\S+")
        .map_err(|error| AutomodError::InvalidRegex(error.to_string()))
}

fn matcher_matches(
    matcher: &CompiledMatcher,
    context: &AutomodContext<'_>,
    normalized: &str,
    content_hash: &[u8; 32],
    history: &VecDeque<RepeatEntry>,
) -> bool {
    match matcher {
        CompiledMatcher::Keyword(matcher) => matcher.is_match(normalized),
        CompiledMatcher::Regex(matcher) => matcher.is_match(context.content),
        CompiledMatcher::InviteLink(matcher) => matcher.is_match(context.content),
        CompiledMatcher::MassMention(limit) => {
            count_mentions(context.content) > usize::from(*limit)
        }
        CompiledMatcher::RepeatedContent {
            threshold,
            window_seconds,
        } => {
            let cutoff = context.now - TimeDelta::seconds(i64::from(*window_seconds));
            let prior = history
                .iter()
                .filter(|entry| entry.created_at >= cutoff && entry.hash == *content_hash)
                .count();
            prior.saturating_add(1) >= usize::from(*threshold)
        }
        CompiledMatcher::NewAccountLink {
            max_account_age_days,
            link,
        } => {
            context.account_created_at
                > context.now - TimeDelta::days(i64::from(*max_account_age_days))
                && link.is_match(context.content)
        }
        CompiledMatcher::Zalgo(limit) => {
            context
                .content
                .chars()
                .filter(|character| is_combining_mark(*character))
                .count()
                > usize::from(*limit)
        }
    }
}

fn count_mentions(content: &str) -> usize {
    content
        .split_whitespace()
        .filter(|part| {
            let candidate = part.trim_matches(|character: char| {
                !character.is_alphanumeric() && !matches!(character, '@' | '_' | '-')
            });
            candidate.starts_with('@') && candidate.len() > 1
        })
        .count()
}

const fn action_priority(action: AutomodAction) -> u8 {
    match action {
        AutomodAction::Ban => 0,
        AutomodAction::Kick => 1,
        AutomodAction::Timeout => 2,
        AutomodAction::Block => 3,
        AutomodAction::Flag => 4,
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use exo_domain::{AutomodRule, AutomodRuleId, AutomodTrigger, GuildId, UserId};

    use super::*;

    fn rule(trigger: AutomodTrigger, action: AutomodAction) -> AutomodRule {
        AutomodRule {
            id: AutomodRuleId::new(),
            guild_id: GuildId::new(),
            name: "Safety rule".into(),
            enabled: true,
            trigger,
            action,
            duration_seconds: (action == AutomodAction::Timeout).then_some(600),
            explanation: "This message matched a server safety rule.".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn context(guild_id: GuildId, user_id: UserId, content: &str) -> AutomodContext<'_> {
        AutomodContext {
            guild_id,
            author_id: user_id,
            content,
            account_created_at: Utc::now() - TimeDelta::hours(1),
            now: Utc::now(),
        }
    }

    #[test]
    fn proof_of_work_is_bound_single_use_and_adaptive() {
        let manager = ProofOfWorkManager::new(8, 12);
        let first = manager.issue("198.51.100.7").unwrap();
        let solution = solve_proof_of_work(&first).unwrap();
        manager.verify("198.51.100.7", &solution).unwrap();
        assert!(manager.verify("198.51.100.7", &solution).is_err());
        for _ in 0..4 {
            let challenge = manager.issue("198.51.100.7").unwrap();
            let solution = solve_proof_of_work(&challenge).unwrap();
            manager.verify("198.51.100.7", &solution).unwrap();
        }
        assert!(manager.issue("198.51.100.7").unwrap().difficulty > 8);
        let other = manager.issue("203.0.113.2").unwrap();
        assert_eq!(other.difficulty, 8);
    }

    #[test]
    fn gcra_allows_exact_burst_then_returns_a_retry() {
        let limiter = GcraLimiter::default();
        let policy = RateLimit::new(3, Duration::from_secs(60));
        assert!(limiter.check("user:1", policy).allowed);
        assert!(limiter.check("user:1", policy).allowed);
        assert!(limiter.check("user:1", policy).allowed);
        let rejected = limiter.check("user:1", policy);
        assert!(!rejected.allowed);
        assert!(rejected.retry_after > Duration::ZERO);
    }

    #[test]
    fn gcra_prunes_only_recovered_buckets_independent_of_current_policy() {
        let limiter = GcraLimiter::default();
        let now = Instant::now();
        {
            let mut arrivals = limiter
                .arrivals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for index in 0..=10_000 {
                arrivals.insert(
                    format!("recovered:{index}"),
                    now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
                );
            }
            arrivals.insert("active".to_owned(), now + Duration::from_secs(60));
        }

        assert!(
            limiter
                .check("new", RateLimit::new(1, Duration::from_secs(86_400)))
                .allowed
        );
        let arrivals = limiter
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(arrivals.len(), 2);
        assert!(arrivals.contains_key("active"));
        assert!(arrivals.contains_key("new"));
    }

    #[test]
    fn automod_matches_literals_regex_links_mentions_and_zalgo() {
        let guild = GuildId::new();
        let user = UserId::new();
        let cases = [
            (
                AutomodTrigger::Keyword {
                    terms: vec!["forbidden phrase".into()],
                },
                "A FORBIDDEN PHRASE appears",
            ),
            (
                AutomodTrigger::Regex {
                    patterns: vec![r"\b\d{3}-\d{3}\b".into()],
                },
                "code 123-456",
            ),
            (
                AutomodTrigger::InviteLink,
                "join https://discord.gg/example",
            ),
            (AutomodTrigger::MassMention { limit: 2 }, "@one @two @three"),
            (
                AutomodTrigger::NewAccountLink {
                    max_account_age_days: 7,
                },
                "read https://example.test",
            ),
            (
                AutomodTrigger::Zalgo {
                    combining_mark_limit: 4,
                },
                "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}",
            ),
        ];
        for (trigger, content) in cases {
            let engine = AutomodEngine::compile(&[rule(trigger, AutomodAction::Block)]).unwrap();
            assert!(engine.evaluate(&context(guild, user, content)).is_some());
        }
    }

    #[test]
    fn repeated_content_tracks_across_evaluations() {
        let rule = rule(
            AutomodTrigger::RepeatedContent {
                threshold: 3,
                window_seconds: 30,
            },
            AutomodAction::Block,
        );
        let guild = rule.guild_id;
        let user = UserId::new();
        let engine = AutomodEngine::compile(&[rule]).unwrap();
        assert!(engine.evaluate(&context(guild, user, "same")).is_none());
        assert!(engine.evaluate(&context(guild, user, "same")).is_none());
        assert!(engine.evaluate(&context(guild, user, "same")).is_some());
    }

    #[test]
    fn invalid_or_catastrophic_style_patterns_are_bounded() {
        let invalid = rule(
            AutomodTrigger::Regex {
                patterns: vec!["(".into()],
            },
            AutomodAction::Block,
        );
        assert!(matches!(
            AutomodEngine::compile(&[invalid]),
            Err(AutomodError::InvalidRegex(_))
        ));
        let oversized = rule(
            AutomodTrigger::Regex {
                patterns: vec!["a".repeat(MAX_PATTERN_BYTES + 1)],
            },
            AutomodAction::Block,
        );
        assert!(matches!(
            AutomodEngine::compile(&[oversized]),
            Err(AutomodError::InvalidPatterns)
        ));
    }
}
