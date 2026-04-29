# Chat4000 CLI — Product Spec

**Status:** Draft (v0.1)
**Owner:** @haimbender
**Last updated:** 2026-04-17

A terminal chat client for OpenClaw agents. Written in Rust. Talks to the same zero-knowledge relay as the Swift/macOS app, uses the same XChaCha20-Poly1305 encryption, shares the same pairing protocol.

Think Claude Code's UX: line-based, streaming, scrollable transcript. Unlike Claude Code, intelligence lives remote — the CLI is a thin encrypted pipe to *your* OpenClaw agent.

---

## 1. Goals

- Parity with Swift client's chat flow: pair, connect, send, receive streamed replies, auto-reconnect.
- Feels native in a terminal: scrollback, inline streaming, Ctrl-C cancels local render, Ctrl-D exits.
- Shares config namespace (XDG) so the CLI and Swift app can both live on the same device.
- Single static binary. Easy install via Homebrew tap and `curl | sh`.
- Forward-compatible with a future agent mode (tool use), kept out of v1 scope.

## 2. Non-goals (v1)

- Image or file attachments.
- Multi-session / per-cwd threads.
- Local tool execution, shell, file edits.
- Background daemon or push notifications.
- Mac App Store distribution (Apple rejects CLI-only apps).
- App Attest on the CLI path (not viable off-App-Store; see §9).

## 3. Users & motivation

Self-hosted OpenClaw operators who live in a terminal and want chat parity with the mobile/desktop apps without context-switching to a GUI. Also useful over SSH, in tmux, on headless Linux boxes.

## 4. User experience

### 4.1 Invocation

```
chat4000                    # start chat; if unpaired, enter interactive pairing
chat4000 pair               # one-shot: pair as joiner (enter code)
chat4000 pair --host        # one-shot: host a pairing (print QR + code)
chat4000 status             # print group id prefix and relay health
chat4000 disconnect         # wipe config, forget group
chat4000 --version
chat4000 --help
```

### 4.2 First run (no config)

No error. Drop into the interactive pair flow:

```
$ chat4000
No group paired yet. Let's pair this device.

Enter pairing code: ABCD-EFGH
• Opening pairing room…
• Verified initiator.
• Received group key.
✓ Paired.

[connected · group 8a3f…]
>
```

### 4.3 Pairing as joiner

Ask for code, run the joiner side of the pairing protocol, persist group key on success. Identical exchange to the Swift app's `PairingCoordinator`.

### 4.4 Pairing as host (`pair --host` or `/pair`)

Generate a pairing code, open a pairing room as the initiator. Print both a visible code and a terminal QR encoding `chat4000://pair?code=XXXX-XXXX`. Auto-detect terminal QR support (unicode block chars); fall back to code-only when the terminal can't render it (non-TTY, limited charset, or explicit `NO_COLOR=1` / `CHAT4000_NO_QR=1`).

```
$ chat4000 pair --host

Pairing code: QZ4K-M7P2       (expires in 5 min)

▄▄▄▄▄▄▄ ▄ ▄  ▄▄▄▄▄▄▄
█ ███ █ ▀█▀▀▀ █ ███ █   ← chat4000://pair?code=QZ4K-M7P2
█ ▀▀▀ █ ▀█▄▀█ █ ▀▀▀ █
▀▀▀▀▀▀▀ ▀ ▀ ▀ ▀▀▀▀▀▀▀

Waiting for peer…
✓ Peer joined.
✓ Key transferred.
```

### 4.5 Chat session

Line-based, scrollback-friendly. Prompt stays at the bottom, streamed reply renders above as chunks arrive, and the transcript can be reviewed with the mouse wheel or `PgUp` / `PgDn`.

```
[connected · group 8a3f…]

> explain the bug in handler.rs:42
⠋ thinking…
The issue at line 42 is that `ctx` is moved into the closure
before the await point, so the borrow at line 45 no longer holds…

>
```

**Rendering rules:**

- Streaming: print each `text_delta` as it arrives, no full-screen redraws.
- Thinking: one-line spinner (`⠋ thinking…`), cleared the moment the first delta lands.
- Status transitions: inline bracketed line, `[reconnecting…]`, `[connected]`, `[disconnected: <reason>]`.
- Ctrl-C during a stream: cancels local render (message keeps accumulating in history). v1 cannot cancel the remote agent.
- Ctrl-C at empty prompt uses the two-step exit prompt. Ctrl-D exits.
- Empty enter: no-op.

### 4.6 Input

Powered by `reedline`. Multi-line input via trailing `\`, `Shift+Enter`, or `Option+Enter` where the terminal supports it. Pasted multi-line content is kept as a single message. Input history stored in `$XDG_DATA_HOME/chat4000/input_history` for up-arrow recall. When you scroll the transcript with the mouse or page keys, `Up` / `Down` stay in transcript navigation until you jump back to the bottom.

### 4.7 Slash commands (in-session)

| Command | Behavior |
|---|---|
| `/help` | List commands |
| `/status` | Connection info (group id prefix, latency) |
| `/pair` | Host an inline pairing to add another device (prints QR, waits) |
| `/disconnect` | Wipe config, exit. Same as `chat4000 disconnect` |
| `/clear` | Clear terminal screen. Does not touch history |
| `/reset-history` | Wipe local transcript; keeps pairing |
| `/quit` | Exit |

### 4.8 History

Always-on. Transcript persisted as append-only JSONL at `$XDG_DATA_HOME/chat4000/history.jsonl`. On startup, the last N messages (default 50) are replayed to give context. `/reset-history` nukes the file. No retention limit in v1 — we rotate later if it becomes a problem.

## 5. Architecture

### 5.1 Crate layout (Cargo workspace)

```
chat4000-cli-rs/
├── Cargo.toml                   (workspace)
├── crates/
│   ├── chat4000-proto/       relay wire format — RelayMessage, InnerMessage
│   ├── chat4000-crypto/      XChaCha20-Poly1305, X25519 pairing, proof, KDF
│   ├── chat4000-relay/       WebSocket client, reconnect, heartbeat, hello
│   └── chat4000/             CLI binary — TUI loop, slash commands, config
├── docs/
│   └── product.md               (this file)
└── README.md
```

Three library crates so a future agent/tool-use binary can reuse proto + crypto + relay.

### 5.2 Key dependencies

| Concern | Crate |
|---|---|
| Async runtime | `tokio` |
| WebSocket | `tokio-tungstenite` |
| XChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) |
| X25519 / ECDH | `x25519-dalek` |
| SHA-256 | `sha2` |
| Secure RNG | `rand_core` with `OsRng` |
| Serde | `serde`, `serde_json` |
| UUID | `uuid` |
| Terminal input | `reedline` |
| Terminal output / colors | `crossterm` |
| QR rendering | `qrcode` (unicode block output) |
| Config / data dirs | `dirs` |
| CLI parsing | `clap` (derive) |
| Logging | `tracing` + `tracing-subscriber` |
| Error | `anyhow` (bin), `thiserror` (libs) |

### 5.3 Config & data layout

XDG, same shape as the Swift app's `GroupConfig` for future import.

```
$XDG_CONFIG_HOME/chat4000/     (fallback ~/.config/chat4000)
└── group-config.json             { groupKeyBase64 }   mode 0600

### 5.4 Relay endpoint

- WebSocket URL: `wss://relay.chat4000.com/ws`
- Health URL: `https://relay.chat4000.com/health`
- Host: `relay.chat4000.com`
- Port: `443`
- Path: `/ws`
- TLS: `true`

$XDG_DATA_HOME/chat4000/       (fallback ~/.local/share/chat4000)
├── history.jsonl                 transcript, append-only
└── input_history                 reedline input ring
```

Config file is `0600` perms on write.

### 5.4 Relay client behavior

Mirrors `RelayClient.swift`:

- Connect → send `hello { role: "app", group_id, device_token: null }`.
- On `hello_ok`: start heartbeat (ping every 30s, reconnect if no pong within 60s).
- On `hello_error`: surface reason, do not retry on auth failures.
- Auto-reconnect with exponential backoff: 2 → 4 → 8 → 16 → 32 → 60s, forever.
- Inner message dispatch: `text`, `text_delta`, `text_end`, `status` → renderer. Unknown types logged and dropped (forward-compat).
- App Attest: **not implemented in the CLI.** The relay must accept app-role clients without attestation. See §9.

### 5.5 Crypto parity

Byte-for-byte identical to `RelayCrypto.swift`:

- **Group ID:** `hex(sha256(group_key))`
- **Pair proof:** `sha256(code || 0x00 || a_salt || 0x00 || b_pub || 0x00 || label)` where label ∈ {`"A"`, `"B"`}
- **Wrap key:** `sha256(x25519_ecdh_shared || "chat4000-pair-wrap-v1")`
- **Message:** `nonce = random(24); ct = xchacha20poly1305_encrypt(group_key, nonce, json(inner))`, wire carries `base64(nonce)` and `base64(ct)`

Interop tests in `chat4000-crypto/tests/` run Swift-generated fixtures through the Rust path and vice versa.

## 6. Protocol parity

`chat4000-proto` implements every message the Swift client knows:

- Pairing: `pair_open`, `pair_ready`, `pair_data {hello|join|proof_b|grant}`, `pair_complete`, `pair_error`
- Auth: `hello`, `hello_ok`, `hello_error`
- Messaging: `msg`, `typing`
- Keepalive: `ping`, `pong`
- Optional future extensions: relay may send unknown `type` values; decoder tolerates them.

Inner message types parsed/emitted: `text`, `text_delta`, `text_end`, `status`, `image` (decoded and skipped with a placeholder in chat render).

## 7. Distribution

### 7.1 Homebrew tap (day one)

- Publish a `chat4000/homebrew-tap` repo with a formula pointing at GitHub Release tarballs.
- Users: `brew install chat4000/tap/chat4000`.
- Release CI (GitHub Actions): build macOS universal (arm64 + x86_64) and Linux (x86_64, aarch64) tarballs, sign, publish release, bump formula SHA.

### 7.2 `curl | sh` installer (day one)

- `curl -sSL https://chat4000.com/install.sh | sh`.
- ~30-line POSIX shell: detect OS/arch, download matching tarball from the latest release, install to `/usr/local/bin` (fallback `~/.local/bin`), verify signature.
- Script lives in the release repo; domain is a redirect to the raw GitHub URL so URL doesn't rot.

### 7.3 crates.io (free, day one)

- `cargo install chat4000` for the Rust crowd. No approval process.

### 7.4 Homebrew core (later)

- Once stable with real adoption: submit to `homebrew-core`. Gets users `brew install chat4000` with no tap prefix, but takes review time and is stricter about versioning.

### 7.5 Not pursuing

- Mac App Store (Apple rejects CLI-only apps).
- Windows (out of scope v1; can revisit).
- Linux distro packages beyond the tarball (deb/rpm nice-to-have, not v1).

## 8. Security model

- The group key is the only durable secret. Possession of it is the entire authorization story for the app role.
- Key is stored on disk at `0600`. No keyring integration in v1 (future work).
- Relay sees only ciphertext + routing metadata. Plaintext never leaves the binary.
- Pairing code is a short low-entropy secret. Mitigations: short TTL (5 min), single-use room, proof exchange binds code to the exact room participants (same as Swift).
- No logging of plaintext messages. `--verbose` / `RUST_LOG` must redact inner bodies.
- No update auto-downloader in v1 (update via `brew upgrade` / `cargo install`).

## 9. Open questions & risks

### 9.1 Relay auth without App Attest — resolved in principle

Confirmed from `AppAttestService.swift:27-33` that Swift macOS builds also skip Attest (`DCAppAttestService.isSupported` returns false off-App-Store). The relay already tolerates non-attested `hello`. We proceed on that assumption. **Action item outside this project:** the relay team should make the policy explicit — require group-key possession proof (decrypt a relay-issued nonce) for any client that doesn't present an Attest token, so the security model doesn't silently rely on a bug-class absence of attestation enforcement.

### 9.2 Agent-side cancel

Ctrl-C during a stream cancels local render but not the remote agent. A `cancel` inner message isn't in the protocol today. Fine for v1; file as future work in the relay/OpenClaw protocol.

### 9.3 Long-lived reconnects

TUI holds the terminal indefinitely. If laptop sleeps for hours, backoff is bounded at 60s, so first wake reconnects within a minute. Fine.

### 9.4 Binary name collision

`chat4000` is unclaimed on crates.io and Homebrew at time of writing. Confirm again before first release.

### 9.5 Telemetry

Swift app sends Sentry + PostHog. Proposal for CLI: **no telemetry in v1.** Reconsider post-launch if we need crash signal; if added it must be opt-in and off by default for a security-sensitive tool.

## 10. Milestones

| Milestone | Scope | Estimate |
|---|---|---|
| **M0 — Proto & crypto foundation** | `chat4000-proto` + `chat4000-crypto` crates with full type coverage and interop tests against Swift fixtures | 3–4 days |
| **M1 — Relay client** | `chat4000-relay` with connect / hello / heartbeat / reconnect; integration test against a local relay stub | 3–4 days |
| **M2 — CLI chat MVP** | `chat4000` binary: config load/save, `reedline` input, streaming render, slash commands (`/help`, `/clear`, `/quit`, `/status`, `/reset-history`). Manual E2E against real relay + OpenClaw plugin | 4–5 days |
| **M3 — Pairing** | Joiner flow, host flow, terminal QR, auto-detect, `chat4000 disconnect` / `/disconnect` | 3 days |
| **M4 — Polish & release** | Typing + thinking indicators, status line, `status` subcommand, GitHub Actions release pipeline, Homebrew tap, install.sh, crates.io publish | 2–3 days |

**Total:** roughly 3 weeks solo.

## 11. Success criteria (v1)

- `brew install chat4000/tap/chat4000 && chat4000` → interactive pair → working chat on macOS arm64 and Linux x86_64.
- Interop: a message sent from the CLI is correctly decrypted and displayed in the Swift iOS app, and vice versa.
- Reconnect survives a 60-second network drop without user intervention.
- Crypto interop tests green: 100% of Swift test vectors decoded by Rust, and all Rust-encoded messages decoded by Swift.
- Zero crashes in a 1-hour continuous chat soak.

## 12. Out of scope → future work

- Local tool use / agent mode (local bash, file edits) — design a protocol extension first.
- Windows build.
- Image attachments (both directions).
- Multi-session / per-directory threads.
- Keyring storage for group key.
- Cancel-in-flight agent response.
- Auto-update mechanism.
