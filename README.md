# EchoVault — security-first personal music streaming (1-Pod, UX-obsessed)

> Private music streaming for homelabs that feels premium and stays lean.
> One Pod. One binary. Passkeys, device-bound tokens, signed URLs, HLS/LL-HLS,
> real-time presence and “listen together”. Security and UX first.

**Project status:** Pre-release / design phase. This repo documents the vision, security model, and MVP scope before code lands.

## Why EchoVault (in one minute)
- **Security without friction**: Passkeys (WebAuthn), device-bound access tokens (DPoP), short-lived signed media URLs.
- **One Pod simplicity**: Rust monolith + embedded UI, SQLite (WAL), minimal memory/CPU.
- **UX**: consistent web/desktop/mobile experience, instant seek (Range + zero-copy), “listen together” via LL-HLS.
- **Homelab-friendly**: mount your `/music`, point your Ingress, done.

> We intentionally **do not** support Subsonic/OpenSubsonic. We trade legacy compatibility for a tighter security model and a unified UX. See [docs/WHY_NOT_SUBSONIC.md](docs/WHY_NOT_SUBSONIC.md).

## What will ship in the MVP
- Passwordless login (Passkeys), device registration, short-lived access.
- Raw streaming with HTTP Range, ETag, HEAD; HLS (Opus/AAC) with shared segments.
- Real-time presence + rooms (“listen together”) over WebSocket.
- Embedded settings site: onboarding, invites, status, metrics.
- Single-container deploy (Docker/Kubernetes), tiny resource footprint.

## Current state
There’s no runnable build yet. We’re finalizing the threat model, public API, and UX flows. Early issues and discussions are open to shape the MVP.

## Contributing
We welcome thoughtful issues and PRs once the MVP branch opens. Read [CONTRIBUTING.md](CONTRIBUTING.md).

## Security
If you discover a vulnerability, please **do not** open a public issue. Follow the process in [SECURITY.md](SECURITY.md).

## License
Apache-2.0 (planned).
