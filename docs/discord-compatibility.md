# Discord compatibility boundary

Discord connectivity is an optional adoption bridge. It is not Exocord's
identity system, message store, or voice backend.

## What standard OAuth can support

The normal Discord OAuth surface supports:

- account linking with `identify`;
- optional Discord server metadata with `guilds`;
- optional linked-account metadata with `connections`.

It does not expose a normal user's relationship list, DM history, or their
existing Discord voice session. Exocord must never ask users for raw tokens,
automate a user account, or ship a self-bot workaround.

Official reference:
[OAuth scopes](https://docs.discord.com/developers/platform/oauth2-and-permissions)
and [User resource](https://docs.discord.com/developers/resources/user).

## The Discord Social SDK option

Discord's Social SDK can provide a unified Discord friend list and, with the
communication scope, limited direct messaging and lobby voice. It is currently
positioned and reviewed as a game SDK:

- development DMs are capped at 100 sends per two hours per application;
- full-release communication limits require a Discord application review;
- the production checklist requires game features including Rich Presence,
  Discord Joins, and full friend access;
- retrieved DM history is capped to 200 messages / 72 hours and requires both
  people to have used the application;
- voice is an application lobby/call integration, not arbitrary attachment to
  an existing Discord server voice channel.

Official reference:
[Communication features](https://docs.discord.com/developers/discord-social-sdk/core-concepts/communication-features),
[Direct messages](https://docs.discord.com/developers/discord-social-sdk/development-guides/sending-direct-messages),
and [platform support](https://docs.discord.com/developers/discord-social-sdk/core-concepts/platform-compatibility).

This makes the Social SDK a useful prototype/partnership path, but not a
dependency Exocord can promise until Discord confirms the product is eligible.

## Product path

1. Exocord accounts and servers work independently.
2. Standard Discord OAuth is an optional, revocable account link.
3. If Discord approves Social SDK use, a proprietary native adapter implements
   the `exo-discord` capability boundary.
4. Discord conversations are visually marked and never silently copied into
   Exocord storage.
5. Exocord-native friends, DMs, servers, and LiveKit voice progressively replace
   the bridge as adoption grows.

The core capability matrix intentionally reports unsupported or approval-gated
features. The UI should use that matrix rather than pretending every linked
account has the same access.
