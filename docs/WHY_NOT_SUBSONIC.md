# Why we don’t support Subsonic / OpenSubsonic

EchoVault optimizes for **security guarantees** and a **uniform, UX** over compatibility.

## Security
- **Legacy auth**: The Subsonic ecosystem still leans on querystring auth and long-lived API keys in many clients. EchoVault uses **Passkeys** and **device-bound tokens (DPoP)** to prevent token replay and sharing.
- **No per-segment guarantees**: We require **short-lived signed URLs** for every media request (including HLS segments) to reduce link leakage. Not a universal assumption in Subsonic clients.
- **Least privilege & audit**: We need per-device rate limits, scoped roles, and audit logs by user/device without relying on external gateways.

## UX
- **Single experience**: Subsonic prioritizes many clients; quality varies (gapless, replay gain, HLS, etc.). EchoVault ships **one coherent UI** across web/desktop/mobile.
- **Real-time by design**: Presence, rooms, and synchronized playback are first-class (WebSocket + server time reference). Not part of the Subsonic contract.

**Trade-off:** We lose immediate compatibility with third-party Subsonic apps and gain a tighter model: stronger security, lower latency, and a consistent UI.
