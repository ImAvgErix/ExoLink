use std::{
    fmt,
    str::FromStr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

/// Exocord's permanent epoch: 2026-01-01T00:00:00Z.
pub const EXOCORD_EPOCH_MILLIS: u64 = 1_767_225_600_000;
const MAX_RELATIVE_MILLIS: u64 = (1 << 41) - 1;
const MAX_SEQUENCE: u16 = (1 << 12) - 1;

/// A positive, time-sortable 64-bit Exocord identifier.
///
/// REST serialization is deliberately a string so JavaScript never rounds it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Snowflake(u64);

impl Snowflake {
    /// Constructs an ID from its wire/database representation.
    ///
    /// # Errors
    ///
    /// Returns [`SnowflakeError::SignBitSet`] when bit 63 is set.
    pub fn from_raw(value: u64) -> Result<Self, SnowflakeError> {
        if value > i64::MAX as u64 {
            return Err(SnowflakeError::SignBitSet);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn timestamp_millis(self) -> u64 {
        (self.0 >> 22) + EXOCORD_EPOCH_MILLIS
    }
}

impl fmt::Display for Snowflake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Snowflake {
    type Err = SnowflakeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = value
            .parse::<u64>()
            .map_err(|_| SnowflakeError::InvalidString)?;
        Self::from_raw(parsed)
    }
}

impl Serialize for Snowflake {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Snowflake {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SnowflakeVisitor;

        impl Visitor<'_> for SnowflakeVisitor {
            type Value = Snowflake;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a decimal snowflake encoded as a string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(SnowflakeVisitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnowflakeError {
    #[error("worker id must be in 0..=31")]
    InvalidWorker,
    #[error("process id must be in 0..=31")]
    InvalidProcess,
    #[error("system clock is before the Exocord epoch")]
    BeforeEpoch,
    #[error("system clock moved backwards from {previous_ms} to {current_ms}")]
    ClockMovedBackwards { previous_ms: u64, current_ms: u64 },
    #[error("snowflake timestamp exceeds the 41-bit lifespan")]
    TimestampOverflow,
    #[error("snowflake sign bit must remain zero")]
    SignBitSet,
    #[error("snowflake must be a decimal string")]
    InvalidString,
    #[error("snowflake generator state is unavailable")]
    StateUnavailable,
    #[error("snowflake sequence is exhausted for the current millisecond")]
    SequenceExhausted,
}

#[derive(Default)]
struct GeneratorState {
    last_millis: u64,
    sequence: u16,
}

/// Thread-safe generator for the permanent `41 + 5 + 5 + 12` layout.
pub struct SnowflakeGenerator {
    worker_id: u8,
    process_id: u8,
    state: Mutex<GeneratorState>,
}

impl SnowflakeGenerator {
    /// Creates one coordinate in the 1,024-generator ID space.
    ///
    /// # Errors
    ///
    /// Returns an error when either coordinate does not fit its five bits.
    pub fn new(worker_id: u8, process_id: u8) -> Result<Self, SnowflakeError> {
        if worker_id > 31 {
            return Err(SnowflakeError::InvalidWorker);
        }
        if process_id > 31 {
            return Err(SnowflakeError::InvalidProcess);
        }
        Ok(Self {
            worker_id,
            process_id,
            state: Mutex::new(GeneratorState::default()),
        })
    }

    /// Generates an ID using the system clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock is before the epoch, exceeds the format
    /// lifespan, or the state mutex is poisoned. Ordinary wall-clock
    /// regressions are absorbed by the generator's monotonic logical clock.
    pub fn generate(&self) -> Result<Snowflake, SnowflakeError> {
        let current_millis = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| SnowflakeError::BeforeEpoch)?
                .as_millis(),
        )
        .map_err(|_| SnowflakeError::TimestampOverflow)?;
        self.generate_logically_at_millis(current_millis)
    }

    /// Generates an ID for a supplied Unix millisecond timestamp.
    ///
    /// This is exposed for deterministic scheduling and tests; production
    /// request paths normally call [`Self::generate`].
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, exhausted sequence space, or
    /// unavailable generator state.
    pub fn generate_at_millis(&self, current_millis: u64) -> Result<Snowflake, SnowflakeError> {
        let relative_millis = current_millis
            .checked_sub(EXOCORD_EPOCH_MILLIS)
            .ok_or(SnowflakeError::BeforeEpoch)?;
        if relative_millis > MAX_RELATIVE_MILLIS {
            return Err(SnowflakeError::TimestampOverflow);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| SnowflakeError::StateUnavailable)?;
        if current_millis < state.last_millis {
            return Err(SnowflakeError::ClockMovedBackwards {
                previous_ms: state.last_millis,
                current_ms: current_millis,
            });
        }
        if current_millis == state.last_millis {
            if state.sequence == MAX_SEQUENCE {
                return Err(SnowflakeError::SequenceExhausted);
            }
            state.sequence += 1;
        } else {
            state.last_millis = current_millis;
            state.sequence = 0;
        }

        let value = (relative_millis << 22)
            | (u64::from(self.worker_id) << 17)
            | (u64::from(self.process_id) << 12)
            | u64::from(state.sequence);
        Snowflake::from_raw(value)
    }

    fn generate_logically_at_millis(
        &self,
        current_millis: u64,
    ) -> Result<Snowflake, SnowflakeError> {
        current_millis
            .checked_sub(EXOCORD_EPOCH_MILLIS)
            .ok_or(SnowflakeError::BeforeEpoch)?;

        let mut state = self
            .state
            .lock()
            .map_err(|_| SnowflakeError::StateUnavailable)?;
        if current_millis > state.last_millis {
            state.last_millis = current_millis;
            state.sequence = 0;
        } else if state.sequence == MAX_SEQUENCE {
            state.last_millis = state
                .last_millis
                .checked_add(1)
                .ok_or(SnowflakeError::TimestampOverflow)?;
            state.sequence = 0;
        } else {
            state.sequence += 1;
        }

        let relative_millis = state
            .last_millis
            .checked_sub(EXOCORD_EPOCH_MILLIS)
            .ok_or(SnowflakeError::BeforeEpoch)?;
        if relative_millis > MAX_RELATIVE_MILLIS {
            return Err(SnowflakeError::TimestampOverflow);
        }
        let value = (relative_millis << 22)
            | (u64::from(self.worker_id) << 17)
            | (u64::from(self.process_id) << 12)
            | u64::from(state.sequence);
        Snowflake::from_raw(value)
    }
}

impl Default for SnowflakeGenerator {
    fn default() -> Self {
        Self {
            worker_id: 0,
            process_id: 0,
            state: Mutex::new(GeneratorState::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_layout_round_trips_time_and_coordinates() {
        let generator = SnowflakeGenerator::new(17, 9).unwrap();
        let timestamp = EXOCORD_EPOCH_MILLIS + 12_345;
        let id = generator.generate_at_millis(timestamp).unwrap();

        assert_eq!(id.timestamp_millis(), timestamp);
        assert_eq!((id.raw() >> 17) & 0b1_1111, 17);
        assert_eq!((id.raw() >> 12) & 0b1_1111, 9);
        assert_eq!(id.raw() & 0x0fff, 0);
    }

    #[test]
    fn ids_are_monotonic_inside_one_millisecond() {
        let generator = SnowflakeGenerator::default();
        let timestamp = EXOCORD_EPOCH_MILLIS + 1;
        let first = generator.generate_at_millis(timestamp).unwrap();
        let second = generator.generate_at_millis(timestamp).unwrap();
        assert!(second > first);
    }

    #[test]
    fn production_generation_absorbs_clock_regressions_and_sequence_pressure() {
        let generator = SnowflakeGenerator::default();
        let timestamp = EXOCORD_EPOCH_MILLIS + 20;
        let first = generator.generate_at_millis(timestamp).unwrap();
        let second = generator
            .generate_logically_at_millis(timestamp - 1)
            .unwrap();
        assert!(second > first);
        assert_eq!(second.timestamp_millis(), timestamp);

        let mut latest = second;
        for _ in 0..MAX_SEQUENCE {
            latest = generator
                .generate_logically_at_millis(timestamp - 1)
                .unwrap();
        }
        assert!(latest > second);
        assert_eq!(latest.timestamp_millis(), timestamp + 1);
    }

    #[test]
    fn json_uses_strings_to_preserve_all_bits() {
        let id = Snowflake::from_raw(i64::MAX as u64).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", i64::MAX));
    }
}
