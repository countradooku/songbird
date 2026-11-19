//! Prompt 10, M4 (D-0123): the device-to-device transfer: QR codes, the Noise `NNpsk0`
//! handshake (a wrong code and a relay in the middle fail; both phones show the same code),
//! a whole history moved over loopback and verified before `OK`, tampering in transit, and a
//! byte-exact handshake vector re-derived by `vectors/transfer_check.py`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::json;
use songbird_backup_format::reader::{Backup, MemoryStaging};
use songbird_backup_format::schema::record::Body;
use songbird_backup_format::synth::{self, Shape};
use songbird_backup_format::{OsRng, RecoveryKey};
use songbird_backup_storage::BackupStore;
use songbird_backup_storage::local::LocalStore;
use songbird_backup_storage::run::{self, Options};
use songbird_backup_storage::transfer::{self, Code, Hello, PipeStore, TransferError};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

fn loopback() -> Vec<IpAddr> {
    vec![IpAddr::from([127, 0, 0, 1])]
}

#[test]
fn qr_codes_round_trip_and_anything_else_is_refused() {
    let c = Code {
        psk: Zeroizing::new([7; 32]),
        port: 47_123,
        addrs: vec![IpAddr::from([192, 168, 1, 20]), "fe80::1".parse().unwrap()],
    };
    let qr = c.to_qr();
    assert!(qr.starts_with("songbird-transfer:"));
    assert_eq!(Code::parse(&qr).unwrap(), c);
    for bad in [
        "songbird-transfer:",
        "songbird-transfer:!!",
        "https://example.com",
        &qr[..qr.len() - 3],
        &format!("{}A", *qr),
    ] {
        assert!(
            matches!(Code::parse(bad), Err(TransferError::Code)),
            "{bad}"
        );
    }
    assert!(!format!("{c:?}").contains("7, 7"));
}

#[test]
fn both_phones_agree_and_another_code_fails() {
    let code = Code {
        psk: Zeroizing::new([1; 32]),
        port: 1,
        addrs: loopback(),
    };
    let (m1, finish) = transfer::initiator_start(&code, None).unwrap();
    assert_eq!(m1.len(), 48);
    let (m2, responder) = transfer::respond(&code, &m1, None).unwrap();
    let initiator = finish(&m2).unwrap();
    assert_eq!(initiator.code, responder.code);
    assert_eq!(initiator.hash, responder.hash);
    // Another code (one bit of the key, or the port, which the prologue binds): refused.
    let mut other = code.clone();
    other.psk[0] ^= 1;
    assert!(transfer::respond(&other, &m1, None).is_err());
    let mut moved = code.clone();
    moved.port = 2;
    assert!(transfer::respond(&moved, &m1, None).is_err());
    // A reply from someone with another code: refused by the initiator.
    let (m1b, finish_b) = transfer::initiator_start(&code, None).unwrap();
    let (m2_other, _) = transfer::respond(
        &other,
        &transfer::initiator_start(&other, None).unwrap().0,
        None,
    )
    .unwrap();
    let _ = m1b;
    assert!(finish_b(&m2_other).is_err());
}

#[test]
fn the_handshake_matches_its_published_vector() {
    let code = Code {
        psk: Zeroizing::new([0x42; 32]),
        port: 50_000,
        addrs: loopback(),
    };
    let (m1, finish) = transfer::initiator_start(&code, Some([0x11; 32])).unwrap();
    let (m2, responder) = transfer::respond(&code, &m1, Some([0x22; 32])).unwrap();
    let i = finish(&m2).unwrap();
    assert_eq!(i.hash, responder.hash);
    let v = json!({
        "protocol": "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        "prologue": hex::encode([b"songbird.v1/transfer\0".as_slice(), &code.payload()].concat()),
        "psk": hex::encode(*code.psk),
        "initiator_ephemeral": hex::encode([0x11; 32]),
        "responder_ephemeral": hex::encode([0x22; 32]),
        "message_1": hex::encode(&m1),
        "message_2": hex::encode(&m2),
        "handshake_hash": hex::encode(i.hash),
        "code": i.code,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/transfer.json");
    if std::env::var_os("SONGBIRD_WRITE_BACKUP_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let published: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v, published);
}

const SHAPE: Shape = Shape {
    seed: 99,
    chats: 6,
    messages_per_chat: 200,
    media_every: 20,
    media_sizes: &[3_000, 1_400_000],
    contacts: 8,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_history_moves_to_a_new_phone_and_is_verified_before_ok() {
    let dir = tempfile::tempdir().unwrap();
    // The new phone listens and shows its code.
    let (listener, code) = transfer::listen(loopback()).await.unwrap();
    let qr = code.to_qr();
    let received: Arc<dyn BackupStore> = Arc::new(LocalStore::new(dir.path().join("incoming")));
    let into = Arc::clone(&received);
    let new_phone = tokio::spawn(async move {
        let ch = transfer::accept(&listener, &code).await.unwrap();
        let shown = ch.code();
        let store = Arc::clone(&into);
        let hello = transfer::receive(ch, into, move |h: Hello| async move {
            // Everything is restored and checked before the old phone hears OK.
            let keys = Arc::new(RecoveryKey::from_secret(*h.secret).derive().unwrap());
            run::restore(store, keys, None, MemoryStaging::default(), 4)
                .await
                .is_ok()
        })
        .await
        .unwrap();
        (shown, hello)
    });
    // The old phone scans, connects, and writes a backup under a one-time key.
    let code = Code::parse(&qr).unwrap();
    let ch = transfer::connect(&code).await.unwrap();
    let shown_old = ch.code();
    let once = RecoveryKey::generate(&mut OsRng).unwrap();
    let hello = Hello {
        account: [5; 16],
        handover: Zeroizing::new([6; 32]),
        device: [7; 16],
        secret: Zeroizing::new(*once.secret()),
    };
    let pipe = Arc::new(PipeStore::new(ch, &hello).await.unwrap());
    let keys = Arc::new(once.derive().unwrap());
    let done = run::backup(
        pipe.clone(),
        Arc::clone(&keys),
        None,
        Options::default(),
        |w| synth::write(w, &SHAPE, 0).map(|_| ()),
    )
    .await
    .unwrap();
    pipe.finish().await.unwrap();
    let (shown_new, got) = new_phone.await.unwrap();
    assert_eq!(shown_old, shown_new, "both phones show the same code");
    assert_eq!(
        (got.account, *got.handover, got.device),
        ([5; 16], [6; 32], [7; 16])
    );
    // The new phone has the whole history.
    let r = run::restore(
        received,
        keys.clone(),
        Some(done.seen),
        MemoryStaging::default(),
        4,
    )
    .await
    .unwrap();
    let b = Backup::new(&keys, &r.opened.manifest, &r.staging);
    let messages = b
        .records()
        .filter(|x| matches!(x.as_ref().unwrap().body, Some(Body::Message(_))))
        .count();
    assert_eq!(messages, 6 * 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_with_another_code_and_tampering_in_transit_both_fail() {
    // A phone with another code connects first: the new phone drops it and keeps waiting.
    let (listener, code) = transfer::listen(loopback()).await.unwrap();
    let real = code.clone();
    let accepting =
        tokio::spawn(async move { transfer::accept(&listener, &real).await.map(|c| c.code()) });
    let mut wrong = code.clone();
    wrong.psk[3] ^= 0x80;
    assert!(matches!(
        transfer::connect(&wrong).await,
        Err(TransferError::Handshake)
    ));
    // The right phone still gets through.
    let ok = transfer::connect(&code).await.unwrap();
    assert_eq!(accepting.await.unwrap().unwrap(), ok.code());

    // A relay that flips one byte of the stream: the receiver refuses the message.
    let (listener, code) = transfer::listen(loopback()).await.unwrap();
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let target = code.port;
    tokio::spawn(async move {
        let (mut a, _) = relay.accept().await.unwrap();
        let mut b = tokio::net::TcpStream::connect(("127.0.0.1", target))
            .await
            .unwrap();
        let (mut ar, mut aw) = a.split();
        let (mut br, mut bw) = b.split();
        let up = async {
            let mut buf = vec![0u8; 1 << 16];
            let mut total = 0usize;
            loop {
                let n = ar.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                // After the handshake (2 + 48 bytes), flip a byte of the first record.
                if total < 60 && total + n > 60 {
                    buf[60 - total] ^= 1;
                }
                total += n;
                if bw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        let down = async {
            let _ = tokio::io::copy(&mut br, &mut aw).await;
        };
        tokio::join!(up, down);
    });
    let real = code.clone();
    let new_phone = tokio::spawn(async move {
        let ch = transfer::accept(&listener, &real).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        transfer::receive(
            ch,
            Arc::new(LocalStore::new(dir.path().join("x"))),
            |_| async { true },
        )
        .await
    });
    let ch = transfer::connect_via(
        &code,
        std::net::SocketAddr::from(([127, 0, 0, 1], relay_port)),
    )
    .await
    .unwrap();
    let hello = Hello {
        account: [1; 16],
        handover: Zeroizing::new([2; 32]),
        device: [3; 16],
        secret: Zeroizing::new([4; 32]),
    };
    let _pipe = PipeStore::new(ch, &hello).await.unwrap();
    // The handshake went through the relay untouched; the first record arrives flipped.
    let r = new_phone.await.unwrap();
    assert!(matches!(r, Err(TransferError::Tampered)), "{r:?}");
}
