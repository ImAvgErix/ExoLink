# Design and integration reference audit

This audit records which ideas from the supplied prototypes and posts belong in
the Windows alpha. The user-supplied `Exocord Client Prototype.zip`, with v14 as
its latest revision, is Exocord's canonical client design. The public artifact
is a visual cross-check. External posts contribute interaction principles only;
they are not dependencies unless their license, accessibility, performance,
and privacy boundary have been verified.

## Adopt now

- Keep the supplied v14 Exocord prototype's macro-layout: a 52 px
  profile/space/channel top bar with no permanent workspace rail, a centered
  message surface, hour-separated message blocks, a 52 px low-chrome composer,
  and a 252 px voice dock that collapses to a 56 px live-call rail.
- Self-host Geist Sans and Geist Mono in the desktop bundle. They improve the
  client and onboarding typography without sending font requests or usage
  metadata to a third party.
- Use motion to explain state: short tab/toggle transitions, typing and
  reconnect indicators, a moving border accent on the active speaker, and
  restrained loading feedback. Every animation is disabled by
  `prefers-reduced-motion`.
- Adapt the border-beam, tab-bar, sidebar, morphing-control, and chat-composer
  references with local CSS. These effects are small enough that importing a
  component framework would cost more bundle weight and control than it saves.
- Retain native inputs and selection behavior. The composer can look refined
  without replacing the caret, IME, clipboard, password, selection, or
  accessibility semantics.
- Treat polished component-library work as a quality checklist: keyboard
  navigation, clear focus, strict TypeScript, theming, and small imports. The
  current purpose-built components remain easier to audit than a second design
  system.

## Optional integrations after the core alpha

### X Chat

The [X Chat API/XDK announcement](https://x.com/cb_doge/status/2082665171332239556)
describes encrypted DMs, groups, media, real-time events, and several SDK
languages. It could become an opt-in bridge, similar to the isolated Discord
compatibility boundary. It must not become Exocord's identity system, message
store, or encryption root.

Before enabling it, verify the official API terms, stable documentation,
account-consent flow, message limits, deletion behavior, and whether clients
can independently authenticate encrypted sessions. The announcement's
temporary 500-message daily allowance is not enough for the main network.

### Grok Voice

Grok Voice fits as an optional bot participant or accessibility tool, not as
the transport for person-to-person calls. xAI exposes a real-time WebSocket
voice API and an official LiveKit integration, which matches Exocord's media
topology:

- [Voice Agent API](https://docs.x.ai/developers/models/voice-agent-api)
- [Realtime voice reference](https://docs.x.ai/developers/rest-api-reference/inference/voice)
- [Current voice pricing](https://x.ai/api/voice)

The safe design is server-side API-key custody, short-lived client secrets or a
server-owned LiveKit participant, explicit per-session activation, a visible
"audio is being sent to xAI" state, and no ambient recording. It remains off
by default because it is metered and sends selected audio outside Exocord's
end-to-end encrypted human call.

### Later product work

- OTP input patterns become useful when verified email and optional MFA land.
- The event-calendar time grid is useful for server events, not basic chat.
- AI memory and AI-thinking animations apply only if Exocord later adds an
  opt-in assistant with a separate retention policy.
- Mobile-only React Native and Expo optimizations can be reconsidered when
  mobile becomes an actual target.

## Reference-by-reference decision

| Reference | Decision for Exocord |
|---|---|
| [James Labi motion variants](https://x.com/JameslabiQ/status/2082481774421266627) | Adapt restraint and hierarchy; do not animate every control. |
| [Shader/staggered text reveal](https://x.com/tjcages/status/2082194167476949000) | Use only for short onboarding/status copy, never message bodies. |
| [Progressive blur](https://x.com/davidmokos_/status/2082582252110643643) | Recreate locally where scroll-edge context needs it; Expo package is irrelevant to Windows. |
| [React Native Plain Text](https://x.com/mdj_dev/status/2082453726707478622) | Skip; Exocord is Tauri/React DOM, not React Native. |
| [Liquid glass navbar](https://x.com/Matthias_Oel/status/2082467199428751635) | Adapt subtle depth and hover feedback; skip the Framer dependency and heavy glass treatment. |
| [AI CSS reference](https://x.com/haaarshsingh/status/2082467766653653282) | Use as a state-design checklist, not a package dependency. |
| [Chat bar](https://x.com/bestdesignsonx/status/2082254779141820786) | Already reflected in the compact secure composer; preserve native text behavior. |
| [Border beam](https://x.com/Jakubantalik/status/2082141784113557790) | Adopted as a lightweight active-speaker state cue. |
| [Liquid carousel](https://x.com/YousufSoomroDev/status/2081794254238523438) | Skip for chat; decorative shader cost has no alpha value. |
| [input-otp](https://x.com/guilherme_rodz/status/2081844350363844678) | Defer until email verification/MFA. |
| [Native Expo blur](https://x.com/rit3zh/status/2081988176131072354) | Skip mobile implementation; WebView2 already supplies native composition/blur. |
| [Unavailable monid.ai post](https://x.com/monid_ai/status/2081825071635775912) | No decision; the referenced content is no longer available. |
| [Fluid control animation](https://x.com/AlbiaHossain/status/2081729488803766746) | Adapt the sense of continuity for state changes, without shader-heavy controls. |
| [Animated bento](https://x.com/marcelkargul/status/2081755696677208362) | Useful for a marketing page, not the dense desktop chat surface. |
| [Sidebar design](https://x.com/startupvisuals/status/2081794720796410115) | Adopt compact modes and strong active-state hierarchy; already present in the workspace rail. |
| [Appica UI](https://x.com/Appica_dev/status/2078160365276319826) | Use its accessibility/theming claims as a checklist; do not replace the audited local system wholesale. |
| [Animated tab bar](https://x.com/uAghazadae/status/2081678105727344780) | Adapt short state transitions and tooltips in the existing channel bar. |
| [AI thinking animations](https://x.com/AdityaSur11/status/2081658349398175863) | Defer with any optional AI assistant. |
| [Gooey select](https://x.com/juli_fella/status/2081712780265074692) | Skip; native select reliability and accessibility win. |
| [Append-only AI memory](https://x.com/VictorTaelin/status/2081453432318132603) | Do not mix into chat retention. AI memory requires a separate opt-in privacy design. |
| [Event-calendar time grid](https://x.com/reui_io/status/2081645308178546843) | Defer to server events. |
| [Avatar dropdown](https://x.com/arknow91/status/2081613049618661543) | Adapt compact profile controls; easter eggs stay nonessential. |
| [Animated custom caret](https://x.com/mak_madd/status/2081430688289755327) | Skip; it increases IME, selection, RTL, and accessibility risk in the most-used control. |
| [Tailwind Variants performance](https://x.com/hero_ui/status/2081395152942211388) | Skip dependency; Exocord does not currently use Tailwind or runtime variant generation. |

## Performance and privacy rules

1. Motion must use transform, opacity, or a bounded background-position change;
   it must not animate message layout.
2. No visual package enters the bundle for a single effect that local CSS can
   express.
3. Controls remain keyboard- and screen-reader-operable, and reduced-motion
   behavior is mandatory.
4. Human voice and messages do not leave Exocord for an AI provider unless a
   user explicitly starts that feature and sees the provider boundary.
5. External bridges never receive the Exocord master identity, MLS secrets, or
   local encryption keys.
