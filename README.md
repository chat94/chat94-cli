# Chat94 CLI (Rust)

Encrypted terminal client for OpenClaw agents.

This repo is an early Rust implementation of the Chat94 CLI described in [docs/product.md](./docs/product.md). It talks to the same relay protocol as the Swift client and shares the same core crypto and pairing model.

## Current Status

Implemented today:

- Cargo workspace with separate crates for protocol, crypto, relay, and CLI
- Relay protocol models and JSON builders/parsers
- Crypto parity helpers for:
  - group ID derivation
  - pairing code normalization and room ID derivation
  - pairing proof generation
  - X25519 wrapping/unwrapping of the group key
  - XChaCha20-Poly1305 message encryption/decryption
- Relay-backed pairing:
  - `chat94 pair`
  - `chat94 pair --host`
  - inline `/pair` from inside chat
- Relay-backed app session:
  - `hello` handshake
  - encrypted send/receive
  - typing events
  - heartbeat tracking
- Interactive terminal session using `reedline`
- File-backed input history
- Local transcript replay and append-only history storage
- Auto-reconnect with exponential backoff
- File-backed logging for info, debug, and exceptions

## Telemetry

chat94 sends anonymous error reports to help us fix bugs faster.

We collect:

- Crash reports and stack traces
- CLI version
- OS platform and architecture
- An anonymous install ID

We do not collect:

- Message content, AI prompts, or AI responses
- Command-line arguments
- Environment variables
- File contents or filesystem paths containing your identity
- API keys, tokens, or credentials
- Your name, email, or system username
- Your IP address

Disable telemetry:

```bash
chat94 telemetry disable
export CHAT94_TELEMETRY_DISABLED=1
chat94 --no-telemetry
```

Check status:

```bash
chat94 telemetry status
```

Privacy policy: https://chat94.com/privacy

Still rough / not done yet:

- End-to-end live validation against a real relay/plugin stack in this repo
- Polished chunk-by-chunk streaming renderer
- Full product-spec UX parity for prompt handling and slash commands
- Packaging / install flow

## Workspace Layout

```text
chat94-cli-rs/
├── crates/
│   ├── chat94/          CLI binary
│   ├── chat94-crypto/   crypto + pairing helpers
│   ├── chat94-proto/    relay wire protocol
│   └── chat94-relay/    websocket session + pairing client
├── docs/
│   └── product.md
├── Cargo.toml
└── README.md
```

## Commands

```bash
chat94
chat94 --log-level debug
chat94 --stdout-logs
chat94 --log-dir /tmp/chat94-logs
chat94 --no-telemetry
chat94 pair
chat94 pair --host
chat94 status
chat94 disconnect
chat94 telemetry status
chat94 telemetry disable
chat94 telemetry enable
```

Useful combinations:

```bash
cargo run -p chat94 --
cargo run -p chat94 -- --log-level debug --stdout-logs
./target/debug/chat94
```

Current in-session commands:

- `/help`
- `/status`
- `/pair`
- `/clear`
- `/reset-history`
- `/disconnect`
- `/quit`

Input tips:

- Mouse wheel scrolls the chat transcript.
- `Up` / `Down` browse your input history when you are back at the bottom of the chat.
- `Shift+Enter` and `Option+Enter` insert a newline.
- `Option+Backspace` deletes the previous word.

## Local Data

The CLI stores:

- config at XDG config dir: `chat94/group-config.json`
- transcript at XDG data dir: `chat94/history.jsonl`
- input history at XDG data dir: `chat94/input_history`
- logs at XDG data dir: `chat94/logs/`
  - `info.log`
  - `debug.log`
  - `exceptions.log`
- telemetry config at `~/.config/chat94/`
  - `install-id`
  - `notice-shown`
  - `telemetry-enabled`

Saved config currently includes:

- shared group key

## Build

```bash
cargo build
./target/debug/chat94 --help
```

## Test

```bash
cargo test
cargo fmt --all
```

Current automated coverage is strongest around protocol and crypto parity.

## Notes

- The CLI is designed to interoperate with the sibling Swift client and plugin repos.
- The relay currently needs to accept CLI app-role clients without App Attest.
- This repo currently prioritizes protocol correctness and incremental CLI bring-up over UI polish.

## Relay

Use this relay:

- WebSocket URL: `wss://relay.chat94.com/ws`
- Health URL: `https://relay.chat94.com/health`

If a client configures parts separately:

- host: `relay.chat94.com`
- port: `443`
- path: `/ws`
- TLS: `true`

## License

chat94 is licensed under the **GNU General Public License v3.0** (GPL-3.0). See the [LICENSE](./LICENSE) file for details.

Copyright © 2026 NeonNode Limited. All rights reserved.

**Commercial licensing:** If you want to use chat94 in a way that GPL-3.0 doesn't allow (e.g. proprietary/closed-source use), contact contact@chat94.com for a commercial license.
