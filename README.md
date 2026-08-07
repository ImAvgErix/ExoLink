# Exocord

**Built quiet. Tuned sharp.**

Native **desktop chat** for servers, DMs, and voice. Rust core, Tauri shell, React UI. Talks to a Postgres-backed server you can run yourself. Local cache and MLS state stay on the device — pure AMOLED black with a mint accent.

[![Release](https://img.shields.io/github/v/release/ImAvgErix/Exocord?style=flat-square&color=111)](https://github.com/ImAvgErix/Exocord/releases/latest)
[![License](https://img.shields.io/github/license/ImAvgErix/Exocord?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Windows%20x64-alpha-0078d4?style=flat-square)](https://github.com/ImAvgErix/Exocord/releases/latest)
[![Stack](https://img.shields.io/badge/Rust%20%7C%20Tauri%20%7C%20React-3ecf8e?style=flat-square)](https://github.com/ImAvgErix/Exocord)

<p align="center">
  <a href="https://github.com/ImAvgErix/Exocord/releases/latest"><strong>Download Exocord</strong></a>
  &nbsp;·&nbsp;
  <a href="CHANGELOG.md">Changelog</a>
  &nbsp;·&nbsp;
  <a href="docs/windows-alpha.md">Docs</a>
  &nbsp;·&nbsp;
  <a href="PRIVACY.md">Privacy</a>
  &nbsp;·&nbsp;
  <a href="https://www.buymeacoffee.com/UhhErix">Support</a>
</p>

<br />

<p align="center">
  <img src="docs/media/chat.png" alt="Exocord server chat" width="720" />
</p>

---

## What it is

A **Windows-native** client for people who want chat and voice without a browser tab farm. Same quiet product language as Exo and Exo OS.

| | |
| --- | --- |
| **Servers & channels** | Guilds, text channels, roles, permissions, invites |
| **DMs & friends** | Direct messages, friend graph, presence, typing |
| **Voice** | LiveKit rooms, devices, screen share, push-to-talk |
| **Encryption** | OpenMLS private traffic, encrypted attachments, SQLCipher local cache |
| **Desktop shell** | Tauri v2, custom chrome, AMOLED UI, restart-safe outbox |
| **Self-host** | Postgres monolith · alpha deploy scripts under `deploy/` |

<p align="center">
  <img src="docs/media/voice.png" alt="Exocord voice" width="720" />
</p>

---

## Status

**Windows alpha.** Working slice: auth, servers, messaging, voice grants, encryption paths, desktop shell.

Expect breaking changes until public beta. Builds are unsigned; SmartScreen may warn. Use official GitHub releases only.

---

## Install

**Needs:** Windows 10/11 x64 · WebView2 (installed when missing)

1. Download **`Exocord.exe`** from [Releases](https://github.com/ImAvgErix/Exocord/releases/latest)  
2. Run the installer — it installs under your user profile, adds a Start menu entry, and launches Exocord  
3. Alpha builds may embed an API URL; generic builds ask once for the HTTPS server  

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows-alpha.ps1
```

Details: [`docs/windows-alpha.md`](docs/windows-alpha.md)

---

## How it works

```
Client (Tauri + React)  ↔  Rust host  ↔  API / gateway  ↔  Postgres + LiveKit
```

---

## Family

| Product | Role |
| --- | --- |
| **[Exo](https://github.com/ImAvgErix/Exo)** | Per-module gaming optimizers |
| **[Exo OS](https://github.com/ImAvgErix/ExoOS)** | Full Windows transform — Balanced or Extreme |
| **[Exocord](https://github.com/ImAvgErix/Exocord)** | Desktop chat & voice (this repo) |
| **[Exo Launcher](https://github.com/ImAvgErix/ExoLauncher)** | One library UI; store clients as invisible backends |

---

## License & privacy

MIT © 2026 Erix ([ImAvgErix](https://github.com/ImAvgErix)) — [LICENSE](LICENSE) · [PRIVACY.md](PRIVACY.md) · [SECURITY.md](SECURITY.md)

<p align="center"><sub>Built quiet. Tuned sharp.</sub></p>
