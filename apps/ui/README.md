# Songbird app (NSH, Rust)

The Songbird client for iOS, Android, macOS, Windows and Linux, written in
Rust on [NSH (Native Shell)](https://nsh.dev) 0.5. See `DESIGN.md` for the
design system and `docs/design/` for the A1 specs.

```sh
cargo check --all-targets                     # type check
cargo test --lib                              # logic tests (store, tokens)
cargo run                                     # the desktop app on this machine
nsh run                                       # the same through the NSH CLI; --target ios, android
nsh test Screens.test.tsx --target macos      # screenshots into shots/
```

## Layout

| Path | Holds |
| --- | --- |
| `theme.json` | The design tokens: one source for colour roles and radii (light, dark). |
| `src/ui/` | The styled component layer: tokens, icons, buttons, rows, inputs, overlays. Features compose only these. |
| `src/theming.rs` | Theme choice: system, light, dark, high contrast, built from `theme.json`. |
| `src/store/` | The UI's view of app-core and its intents. **Mocked** until `crates/app-core` (A2) exists. |
| `src/nav.rs`, `src/shell.rs` | Navigation and the two layouts (phone tabs; desktop rail + list + detail). |
| `src/features/` | One module per area of the app prompt set (A4–A15). |

## What is mocked

app-core does not exist yet, so the store keeps seeded data in memory and
simulates the network (status ticks advance on timers, contacts type and
reply, calls ring and connect without media). Each mock is marked
`// mock:` in the code with the real app-core call it stands for. No
security claim in the UI depends on a mock: copy describes the real product.

## The real backend

You → Server connection turns it on. What runs live today, and what the app
never sends, is in `src/backend/mod.rs`. To run a local server for the app:

```sh
cargo xtask compose up            # from the repository root: the stores
scripts/dev-app-backend.sh        # api on 127.0.0.1:8443, delivery on 127.0.0.1:9201
scripts/dev-app-backend.sh invite # mint an invite code
```
