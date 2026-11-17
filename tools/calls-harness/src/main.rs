//! Prompt 7's E2EE harness (D-0089): real LiveKit clients (the Rust SDK on libwebrtc) with E2EE
//! on, joining with Songbird's tickets and keys:
//!
//! 1. **connect**: a 1:1 call keyed from a `call_secret` (PROTOCOL §8.2); Bob decodes Alice's video.
//! 2. **wrong key**: Mallory, admitted to the same room with keys from another secret, decodes
//!    nothing of it.
//! 3. **rotation**: a group call keyed from a real OpenMLS group's exporter; Alice removes Carol
//!    (a commit, a new epoch); Alice and Bob switch to the next key index; Bob keeps decoding,
//!    Carol, still connected to the SFU with the old epoch's keys, decodes nothing more.
//!
//! Tickets come from `songbird-calls` exactly as `api` issues them (rooms with caps, per-room
//! pseudonyms, the least grants). Media is synthetic video: flat frames of a known brightness, so a
//! decoded frame proves decryption.
//!
//! ```text
//! cargo run --release -- <ws url> <http url> <api key> <api secret>
//! ```
//! The LiveKit node must advertise an address this machine reaches (`rtc.node_ip`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use futures_util::StreamExt as _;
use livekit::e2ee::key_provider::{KeyProvider, KeyProviderOptions};
use livekit::e2ee::{E2eeOptions, EncryptionType};
use livekit::id::ParticipantIdentity;
use livekit::options::TrackPublishOptions;
use livekit::prelude::*;
use livekit::webrtc::prelude::{I420Buffer, VideoFrame, VideoResolution, VideoRotation};
use livekit::webrtc::video_source::RtcVideoSource;
use livekit::webrtc::video_source::native::NativeVideoSource;
use livekit::webrtc::video_stream::native::NativeVideoStream;
use songbird_calls::{CallLimits, Calls, Media, Publish, RoomId};
use songbird_content::call::{EpochSecret, GROUP_EXPORTER_LABEL, GROUP_EXPORTER_LEN};
use songbird_groups::Limits;
use songbird_groups_harness::{Device, Dir, id_from, server_create, welcome_of};
use songbird_types::{AccountId, DeviceId};

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;
/// The brightness Alice sends; a decoded frame within this distance of it is Alice's.
const LUMA: u8 = 200;
const LUMA_SLACK: f64 = 30.0;

fn random32() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("the system's random source");
    k
}

/// One participant: its room, its key provider and its identity.
struct Peer {
    room: Room,
    keys: KeyProvider,
    identity: String,
    good: Arc<AtomicU64>,
    subscribed: Arc<AtomicU64>,
    states: Arc<parking_lot_free::States>,
}

/// A tiny shared record of E2EE states seen, by remote identity.
mod parking_lot_free {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use livekit::webrtc::native::frame_cryptor::EncryptionState;

    #[derive(Default)]
    pub struct States(Mutex<HashMap<String, Vec<EncryptionState>>>);

    impl States {
        pub fn push(&self, who: String, s: EncryptionState) {
            if let Ok(mut m) = self.0.lock() {
                m.entry(who).or_default().push(s);
            }
        }

        pub fn of(&self, who: &str) -> Vec<EncryptionState> {
            self.0
                .lock()
                .map(|m| m.get(who).cloned().unwrap_or_default())
                .unwrap_or_default()
        }
    }
}

fn mean(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    b.iter().map(|x| f64::from(*x)).sum::<f64>() / b.len() as f64
}

/// Joins `room` with `token` and E2EE keys `keys`; counts decoded frames that look like Alice's.
async fn join(
    name: &'static str,
    url: &str,
    token: &str,
    identity: String,
    keys: KeyProvider,
) -> anyhow::Result<Peer> {
    let mut options = RoomOptions::default();
    options.encryption = Some(E2eeOptions {
        encryption_type: EncryptionType::Gcm,
        key_provider: keys.clone(),
    });
    options.auto_subscribe = true;
    let (room, mut events) = Room::connect(url, token, options)
        .await
        .with_context(|| format!("{name} connects"))?;
    let good = Arc::new(AtomicU64::new(0));
    let subscribed = Arc::new(AtomicU64::new(0));
    let subs = Arc::clone(&subscribed);
    let states = Arc::new(parking_lot_free::States::default());
    let (g, st) = (Arc::clone(&good), Arc::clone(&states));
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                RoomEvent::TrackSubscribed {
                    track: RemoteTrack::Video(t),
                    ..
                } => {
                    subs.fetch_add(1, Ordering::Relaxed);
                    let g = Arc::clone(&g);
                    tokio::spawn(async move {
                        let mut stream = NativeVideoStream::new(t.rtc_track());
                        while let Some(frame) = stream.next().await {
                            let i420 = frame.buffer.to_i420();
                            let (y, u, v) = i420.data();
                            let ok = (mean(y) - f64::from(LUMA)).abs() < LUMA_SLACK
                                && (mean(u) - 128.0).abs() < LUMA_SLACK
                                && (mean(v) - 128.0).abs() < LUMA_SLACK;
                            if ok {
                                g.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
                RoomEvent::E2eeStateChanged { participant, state } => {
                    st.push(participant.identity().to_string(), state);
                }
                _ => {}
            }
        }
    });
    Ok(Peer {
        room,
        keys,
        identity,
        good,
        subscribed,
        states,
    })
}

fn flat_frame() -> I420Buffer {
    let mut buf = I420Buffer::new(WIDTH, HEIGHT);
    let (y, u, v) = buf.data_mut();
    y.fill(LUMA);
    u.fill(128);
    v.fill(128);
    buf
}

/// Publishes flat frames of brightness [`LUMA`] at 15 frames a second until the task is dropped.
async fn publish_video(peer: &Peer) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let source = NativeVideoSource::new(
        VideoResolution {
            width: WIDTH,
            height: HEIGHT,
        },
        false,
    );
    let track =
        LocalVideoTrack::create_video_track("camera", RtcVideoSource::Native(source.clone()));
    peer.room
        .local_participant()
        .publish_track(
            LocalTrack::Video(track),
            TrackPublishOptions {
                source: TrackSource::Camera,
                ..TrackPublishOptions::default()
            },
        )
        .await
        .context("publish video")?;
    Ok(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(66));
        let mut ts: i64 = 0;
        loop {
            tick.tick().await;
            ts += 66_000;
            let frame = VideoFrame {
                rotation: VideoRotation::VideoRotation0,
                timestamp_us: ts,
                frame_metadata: None,
                buffer: flat_frame(),
            };
            source.capture_frame(&frame);
        }
    }))
}

/// Gives every listed identity its sender key at `index`, from `secret`.
fn install(
    keys: &KeyProvider,
    secret: &EpochSecret,
    identities: &[&str],
    index: i32,
) -> anyhow::Result<()> {
    for id in identities {
        let k = secret.sender_key(id.as_bytes())?;
        ensure!(
            keys.set_key(&ParticipantIdentity(id.to_string()), index, k.to_vec()),
            "set_key"
        );
    }
    Ok(())
}

/// Switches this peer's own sending to `index` (its local frame cryptors).
fn send_with(peer: &Peer, index: i32) {
    for ((who, _), cryptor) in peer.room.e2ee_manager().frame_cryptors() {
        if who.to_string() == peer.identity {
            cryptor.set_key_index(index);
        }
    }
}

async fn wait_for(peer: &Peer, at_least: u64, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if peer.good.load(Ordering::Relaxed) >= at_least {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    peer.good.load(Ordering::Relaxed) >= at_least
}

fn report(ok: bool, what: &str) -> bool {
    println!("{} {what}", if ok { "PASS" } else { "FAIL" });
    ok
}

fn provider() -> KeyProvider {
    KeyProvider::new(KeyProviderOptions::default())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, ws, http, key, secret] = args.as_slice() else {
        bail!("usage: calls-harness <ws url> <http url> <api key> <api secret>");
    };
    let calls = Calls::new(
        &random32(),
        key,
        secret.clone().into(),
        ws,
        http,
        None,
        CallLimits::default(),
    )
    .map_err(anyhow::Error::msg)?;
    let device = |n: u16| DeviceId::from_bytes(id_from(n, 0xD0));
    let mut all = true;

    // 1. A 1:1 call: keys from the offer's call_secret.
    let room = RoomId::random().context("room")?;
    calls
        .open_room(&room, Media::Video)
        .await
        .map_err(anyhow::Error::msg)?;
    let alice_t = calls.ticket(&room, &device(1), Publish::Everything)?;
    let bob_t = calls.ticket(&room, &device(2), Publish::Everything)?;
    let call_secret = random32();
    let epoch = EpochSecret::one_to_one(room.as_bytes(), &call_secret)?;
    let ids = [alice_t.identity.as_str(), bob_t.identity.as_str()];
    let (ka, kb) = (provider(), provider());
    install(&ka, &epoch, &ids, 0)?;
    install(&kb, &epoch, &ids, 0)?;
    let alice = join("alice", ws, &alice_t.token, alice_t.identity.clone(), ka).await?;
    let bob = join("bob", ws, &bob_t.token, bob_t.identity.clone(), kb).await?;
    let sending = publish_video(&alice).await?;
    all &= report(
        wait_for(&bob, 10, Duration::from_secs(20)).await,
        "connect: Bob decodes Alice's end-to-end encrypted video",
    );
    let encrypted = bob
        .room
        .remote_participants()
        .values()
        .flat_map(|p| p.track_publications().into_values().collect::<Vec<_>>())
        .all(|p| p.encryption_type() == EncryptionType::Gcm);
    all &= report(
        encrypted,
        "connect: the SFU lists Alice's track as AES-GCM encrypted",
    );

    // 2. Mallory is admitted to the room but holds keys from another secret.
    let mallory_t = calls.ticket(&room, &device(3), Publish::Everything)?;
    let wrong = EpochSecret::one_to_one(room.as_bytes(), &random32())?;
    let km = provider();
    install(&km, &wrong, &ids, 0)?;
    let mallory = join(
        "mallory",
        ws,
        &mallory_t.token,
        mallory_t.identity.clone(),
        km,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let m_good = mallory.good.load(Ordering::Relaxed);
    let m_states = mallory.states.of(&alice_t.identity);
    let m_subs = mallory.subscribed.load(Ordering::Relaxed);
    all &= report(
        m_subs >= 1 && m_good == 0,
        &format!(
            "wrong key: Mallory, subscribed to Alice's video ({m_subs} track), decodes no frame of it (states seen: {m_states:?})"
        ),
    );
    sending.abort();
    for p in [&alice, &bob, &mallory] {
        let _ = p.room.close().await;
    }

    // 3. A group call keyed from a real MLS group; a removal rotates the keys.
    let mut dir = Dir::default();
    let acc = |n: u16| AccountId::from_bytes(id_from(n, 0xA0));
    let mut a = Device::new(11, acc(11), &mut dir);
    let mut b = Device::new(12, acc(12), &mut dir);
    let mut c = Device::new(13, acc(13), &mut dir);
    let ds = server_create(&mut a, &dir);
    let commit = a.add(&[b.key_package(), c.key_package()]);
    let (ds, _) = ds
        .apply_commit(&a.id, &commit, &dir, &Limits::default())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    a.merge();
    let tree = ds.ratchet_tree().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    b.join(&welcome_of(&commit), &tree);
    c.join(&welcome_of(&commit), &tree);
    let room = RoomId::random().context("room")?;
    calls
        .open_room(&room, Media::Video)
        .await
        .map_err(anyhow::Error::msg)?;
    let exported = |d: &Device| -> anyhow::Result<EpochSecret> {
        let x = d.export(GROUP_EXPORTER_LABEL, room.as_bytes(), GROUP_EXPORTER_LEN);
        Ok(EpochSecret::group(
            x.try_into()
                .map_err(|_| anyhow::anyhow!("exporter length"))?,
            d.epoch(),
        ))
    };
    let tickets: Vec<_> = [&a, &b, &c]
        .iter()
        .map(|d| calls.ticket(&room, &d.id, Publish::Everything))
        .collect::<Result<_, _>>()?;
    let ids: Vec<&str> = tickets.iter().map(|t| t.identity.as_str()).collect();
    let e1 = [exported(&a)?, exported(&b)?, exported(&c)?];
    let i1 = i32::try_from(e1[0].key_index())?;
    let providers = [provider(), provider(), provider()];
    for (kp, secret) in providers.iter().zip(&e1) {
        install(kp, secret, &ids, i1)?;
    }
    let names = ["alice", "bob", "carol"];
    let mut peers = Vec::new();
    for ((t, kp), name) in tickets.iter().zip(providers).zip(names) {
        peers.push(join(name, ws, &t.token, t.identity.clone(), kp).await?);
    }
    let sending = publish_video(&peers[0]).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    send_with(&peers[0], i1);
    all &= report(
        wait_for(&peers[1], 10, Duration::from_secs(20)).await
            && wait_for(&peers[2], 10, Duration::from_secs(20)).await,
        &format!(
            "rotation: at epoch {} (key index {i1}) Bob and Carol decode Alice",
            e1[0].epoch()
        ),
    );

    // Alice removes Carol: a commit, a new epoch, keys Carol cannot derive.
    let removal = a.remove(&[c.leaf()]);
    ds.apply_commit(&a.id, &removal, &dir, &Limits::default())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    a.merge();
    b.receive(&removal);
    let e2 = [exported(&a)?, exported(&b)?];
    let i2 = i32::try_from(e2[0].key_index())?;
    ensure!(i2 != i1, "a new epoch, a new key index");
    install(&peers[0].keys, &e2[0], &ids, i2)?;
    install(&peers[1].keys, &e2[1], &ids, i2)?;
    // PROTOCOL §8.2: install at once, send with the new index a second later.
    tokio::time::sleep(Duration::from_secs(1)).await;
    send_with(&peers[0], i2);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (bob_before, carol_before) = (
        peers[1].good.load(Ordering::Relaxed),
        peers[2].good.load(Ordering::Relaxed),
    );
    tokio::time::sleep(Duration::from_secs(8)).await;
    let bob_after = peers[1].good.load(Ordering::Relaxed) - bob_before;
    let carol_after = peers[2].good.load(Ordering::Relaxed) - carol_before;
    all &= report(
        bob_after >= 10,
        &format!(
            "rotation: after the removal (epoch {}, index {i2}) Bob still decodes ({bob_after} frames in 8 s)",
            e2[0].epoch()
        ),
    );
    all &= report(
        carol_after == 0,
        &format!(
            "rotation: Carol, removed but still connected, decodes nothing ({carol_after} frames; states seen: {:?})",
            peers[2].states.of(&tickets[0].identity)
        ),
    );
    sending.abort();
    for p in &peers {
        let _ = p.room.close().await;
    }
    if all {
        println!("calls-harness: all checks passed");
        Ok(())
    } else {
        bail!("calls-harness: a check failed")
    }
}
