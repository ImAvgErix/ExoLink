use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::{GuildId, RoleId, UserId};

bitflags! {
    /// Permanent permission allocation from `03-identity-crypto.md` §6.1.
    ///
    /// Gaps are intentional growth space. Bits 59–63 must remain unallocated.
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(transparent)]
    pub struct GuildPermissions: u64 {
        const CREATE_INVITE            = 1 << 0;
        const KICK_MEMBERS             = 1 << 1;
        const BAN_MEMBERS              = 1 << 2;
        const ADMINISTRATOR            = 1 << 3;
        const MANAGE_CHANNELS          = 1 << 4;
        const MANAGE_GUILD             = 1 << 5;
        const VIEW_AUDIT_LOG           = 1 << 6;
        const MANAGE_ROLES             = 1 << 7;
        const MANAGE_WEBHOOKS          = 1 << 8;
        const MANAGE_EMOJI             = 1 << 9;

        const CHANGE_NICKNAME          = 1 << 10;
        const MANAGE_NICKNAMES         = 1 << 11;
        const MODERATE_MEMBERS         = 1 << 12;
        const VIEW_MEMBER_LIST         = 1 << 13;

        const VIEW_CHANNEL             = 1 << 16;
        const SEND_MESSAGES            = 1 << 17;
        const SEND_MESSAGES_IN_DM      = 1 << 18;
        const EMBED_LINKS              = 1 << 19;
        const ATTACH_FILES             = 1 << 20;
        const ADD_REACTIONS            = 1 << 21;
        const USE_EXTERNAL_EMOJI       = 1 << 22;
        const MENTION_EVERYONE         = 1 << 23;
        const MANAGE_MESSAGES          = 1 << 24;
        const READ_MESSAGE_HISTORY     = 1 << 25;
        const SEND_TTS_MESSAGES        = 1 << 26;
        const MANAGE_PINS              = 1 << 27;
        const BYPASS_SLOWMODE          = 1 << 28;

        const CONNECT                  = 1 << 32;
        const SPEAK                    = 1 << 33;
        const STREAM                   = 1 << 34;
        const MUTE_MEMBERS             = 1 << 35;
        const DEAFEN_MEMBERS           = 1 << 36;
        const MOVE_MEMBERS             = 1 << 37;
        const USE_VAD                  = 1 << 38;
        const PRIORITY_SPEAKER         = 1 << 39;
        const MANAGE_VOICE_CHANNEL     = 1 << 40;

        const MANAGE_AUTOMOD           = 1 << 48;
        const VIEW_AUTOMOD_ALERTS      = 1 << 49;
        const MANAGE_INTEGRATIONS      = 1 << 50;
        const USE_APPLICATION_COMMANDS = 1 << 51;

        const ENABLE_E2EE              = 1 << 56;
        const MANAGE_E2EE_MEMBERS      = 1 << 57;
    }
}

impl GuildPermissions {
    pub const MEMBER_DEFAULT: Self = Self::VIEW_CHANNEL
        .union(Self::SEND_MESSAGES)
        .union(Self::ADD_REACTIONS)
        .union(Self::READ_MESSAGE_HISTORY)
        .union(Self::VIEW_MEMBER_LIST)
        .union(Self::CONNECT)
        .union(Self::SPEAK)
        .union(Self::USE_VAD);

    pub const ALL_GUILD: Self = Self::from_bits_retain(
        Self::all().bits() & !(Self::ENABLE_E2EE.bits() | Self::MANAGE_E2EE_MEMBERS.bits()),
    );

    pub const ALL: Self = Self::all();
}

#[derive(Clone, Copy, Debug)]
pub struct RoleGrant {
    pub role_id: RoleId,
    pub permissions: GuildPermissions,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChannelOverride {
    pub role_id: Option<RoleId>,
    pub user_id: Option<UserId>,
    pub allow: GuildPermissions,
    pub deny: GuildPermissions,
}

pub struct PermissionContext<'a> {
    pub guild_id: GuildId,
    pub guild_owner_id: UserId,
    pub user_id: UserId,
    pub everyone_role_id: RoleId,
    pub everyone: GuildPermissions,
    pub roles: &'a [RoleGrant],
    pub overrides: &'a [ChannelOverride],
    pub timed_out: bool,
}

pub struct PermissionResolver;

impl PermissionResolver {
    #[must_use]
    pub fn resolve(context: &PermissionContext<'_>) -> GuildPermissions {
        if context.guild_owner_id == context.user_id {
            return GuildPermissions::ALL;
        }

        let mut permissions = context.everyone;
        for role in context.roles {
            permissions |= role.permissions;
        }

        if permissions.contains(GuildPermissions::ADMINISTRATOR) {
            let mut administrator = GuildPermissions::ALL_GUILD;
            if context.timed_out {
                administrator &=
                    GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY;
            }
            return administrator;
        }

        if let Some(everyone_rule) = context
            .overrides
            .iter()
            .find(|rule| rule.role_id == Some(context.everyone_role_id))
        {
            permissions.remove(everyone_rule.deny);
            permissions.insert(everyone_rule.allow);
        }

        let role_ids = context
            .roles
            .iter()
            .map(|role| role.role_id)
            .collect::<std::collections::HashSet<_>>();
        let mut role_allow = GuildPermissions::empty();
        let mut role_deny = GuildPermissions::empty();
        for rule in context.overrides {
            if rule.user_id.is_none() && rule.role_id.is_some_and(|id| role_ids.contains(&id)) {
                role_allow |= rule.allow;
                role_deny |= rule.deny;
            }
        }
        permissions.remove(role_deny);
        permissions.insert(role_allow);

        if let Some(member_rule) = context
            .overrides
            .iter()
            .find(|rule| rule.user_id == Some(context.user_id))
        {
            permissions.remove(member_rule.deny);
            permissions.insert(member_rule.allow);
        }

        if context.timed_out {
            permissions &= GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY;
        }

        if !permissions.contains(GuildPermissions::VIEW_CHANNEL) {
            permissions.remove(
                GuildPermissions::SEND_MESSAGES
                    | GuildPermissions::ADD_REACTIONS
                    | GuildPermissions::ATTACH_FILES
                    | GuildPermissions::EMBED_LINKS
                    | GuildPermissions::READ_MESSAGE_HISTORY
                    | GuildPermissions::MANAGE_MESSAGES,
            );
        }

        permissions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context_ids() -> (GuildId, RoleId, UserId, UserId) {
        (GuildId::new(), RoleId::new(), UserId::new(), UserId::new())
    }

    #[test]
    fn allocation_matches_the_permanent_contract() {
        assert_eq!(GuildPermissions::ADMINISTRATOR.bits(), 1 << 3);
        assert_eq!(GuildPermissions::VIEW_CHANNEL.bits(), 1 << 16);
        assert_eq!(GuildPermissions::CONNECT.bits(), 1 << 32);
        assert_eq!(GuildPermissions::ENABLE_E2EE.bits(), 1 << 56);
        assert_eq!(GuildPermissions::ALL.bits() >> 59, 0);
    }

    #[test]
    fn owner_receives_every_allocated_permission() {
        let (guild, everyone_role, owner, _) = context_ids();
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: owner,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::empty(),
            roles: &[],
            overrides: &[],
            timed_out: false,
        };

        assert_eq!(PermissionResolver::resolve(&context), GuildPermissions::ALL);
    }

    #[test]
    fn member_override_wins_over_role_override() {
        let (guild, everyone_role, user, owner) = context_ids();
        let role = RoleId::new();
        let roles = [RoleGrant {
            role_id: role,
            permissions: GuildPermissions::MEMBER_DEFAULT,
        }];
        let overrides = [
            ChannelOverride {
                role_id: Some(role),
                deny: GuildPermissions::SEND_MESSAGES,
                ..Default::default()
            },
            ChannelOverride {
                user_id: Some(user),
                allow: GuildPermissions::SEND_MESSAGES,
                ..Default::default()
            },
        ];
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: user,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::empty(),
            roles: &roles,
            overrides: &overrides,
            timed_out: false,
        };

        assert!(PermissionResolver::resolve(&context).contains(GuildPermissions::SEND_MESSAGES));
    }

    #[test]
    fn administrator_bypasses_channel_overwrites() {
        let (guild, everyone_role, user, owner) = context_ids();
        let overrides = [ChannelOverride {
            role_id: Some(everyone_role),
            deny: GuildPermissions::VIEW_CHANNEL | GuildPermissions::SEND_MESSAGES,
            ..Default::default()
        }];
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: user,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::ADMINISTRATOR,
            roles: &[],
            overrides: &overrides,
            timed_out: false,
        };

        assert_eq!(
            PermissionResolver::resolve(&context),
            GuildPermissions::ALL_GUILD
        );
    }

    #[test]
    fn timeout_still_restricts_an_administrator() {
        let (guild, everyone_role, user, owner) = context_ids();
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: user,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::ADMINISTRATOR,
            roles: &[],
            overrides: &[],
            timed_out: true,
        };

        assert_eq!(
            PermissionResolver::resolve(&context),
            GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY
        );
    }

    #[test]
    fn timeout_strips_send_and_voice_permissions() {
        let (guild, everyone_role, user, owner) = context_ids();
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: user,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::MEMBER_DEFAULT,
            roles: &[],
            overrides: &[],
            timed_out: true,
        };
        let resolved = PermissionResolver::resolve(&context);
        assert_eq!(
            resolved,
            GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY
        );
    }

    #[test]
    fn hidden_channel_collapses_implied_permissions() {
        let (guild, everyone_role, user, owner) = context_ids();
        let context = PermissionContext {
            guild_id: guild,
            guild_owner_id: owner,
            user_id: user,
            everyone_role_id: everyone_role,
            everyone: GuildPermissions::SEND_MESSAGES | GuildPermissions::ATTACH_FILES,
            roles: &[],
            overrides: &[],
            timed_out: false,
        };
        let resolved = PermissionResolver::resolve(&context);
        assert!(
            !resolved.intersects(GuildPermissions::SEND_MESSAGES | GuildPermissions::ATTACH_FILES)
        );
    }
}
