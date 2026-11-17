# calls-harness

Prompt 7's E2EE harness (D-0089): LiveKit's Rust SDK (`livekit` 0.11, libwebrtc) with E2EE on,
admitted with tickets from `songbird-calls` and keyed by `songbird_content::call`, with a real
OpenMLS group for the rotation case. It checks that:

1. a 1:1 call connects and Bob decodes Alice's encrypted video, and the SFU lists the track as
   AES-GCM encrypted;
2. Mallory, admitted to the same room with keys from another secret, subscribes to Alice's video
   and decodes nothing of it;
3. in a group call keyed from the MLS exporter, after Alice removes Carol (a commit, a new epoch),
   Bob keeps decoding at the new key index and Carol, still connected, decodes nothing.

Not part of the workspace or CI's fast tier: it links libwebrtc (hundreds of MB, downloaded at
build time).

```bash
# Windows: a short target directory (libwebrtc's headers exceed MAX_PATH under a deep one);
# .cargo/config.toml links the static C runtime, as libwebrtc's prebuilt libraries do.
CARGO_TARGET_DIR=C:/Users/<short>/.sbh cargo build --release
calls-harness ws://127.0.0.1:47880 http://127.0.0.1:47880 <api key> <api secret>
```

The LiveKit node must create no room on join (`auto_create: false`, as deployed) and advertise an
address this machine reaches that is not loopback (libwebrtc gathers no loopback candidates): with
podman on WSL, the VM's own address (`podman machine ssh ip -4 addr show eth0`) as `rtc.node_ip`.
