//! The test vectors published in `docs/PROTOCOL.md` §13. Changing an encoding fails here first.
#![allow(clippy::unwrap_used, reason = "tests")]

use bytes::Bytes;
use songbird_proto::frame::{Recipient, RejectReason, SendFrame, SendStatus};
use songbird_proto::{ClientFrame, Limits, ServerFrame};
use songbird_types::DeviceId;

fn unhex(s: &str) -> Bytes {
    Bytes::from(hex::decode(s.replace(' ', "")).unwrap())
}

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

#[test]
fn client_frames() {
    let cases = [
        (ClientFrame::Ack { up_to_seq: 42 }, "02 000000000000002a"),
        (
            ClientFrame::Ephemeral {
                to: dev(0x44),
                payload: Bytes::from_static(b"typing"),
            },
            "03 44444444444444444444444444444444 747970696e67",
        ),
        (
            ClientFrame::Send(SendFrame {
                req_id: 7,
                idempotency_key: [0x11; 16],
                recipients: vec![
                    Recipient {
                        device: dev(0x22),
                        envelope: Bytes::from_static(b"abc"),
                    },
                    Recipient {
                        device: dev(0x33),
                        envelope: Bytes::from_static(b"z"),
                    },
                ],
            }),
            "01 00000007 11111111111111111111111111111111 0002 \
             22222222222222222222222222222222 00000003 616263 \
             33333333333333333333333333333333 00000001 7a",
        ),
    ];
    for (frame, hex) in cases {
        let want = unhex(hex);
        assert_eq!(frame.to_bytes(), want);
        assert_eq!(ClientFrame::decode(&want, &Limits::DEFAULT).unwrap(), frame);
    }
}

#[test]
fn server_frames() {
    let cases = [
        (
            ServerFrame::Deliver {
                seq: 1,
                envelope: Bytes::from_static(b"envelope"),
            },
            "81 0000000000000001 656e76656c6f7065",
        ),
        (
            ServerFrame::SendResult {
                req_id: 7,
                status: SendStatus::Accepted,
            },
            "82 00000007 00",
        ),
        (
            ServerFrame::SendResult {
                req_id: 7,
                status: SendStatus::Rejected {
                    reason: RejectReason::RateLimited,
                    retry_after_ms: 500,
                },
            },
            "82 00000007 01 0001 000001f4",
        ),
    ];
    for (frame, hex) in cases {
        let want = unhex(hex);
        assert_eq!(frame.to_bytes(), want);
        assert_eq!(ServerFrame::decode(&want, &Limits::DEFAULT).unwrap(), frame);
    }
}

#[test]
fn auth_transcript() {
    let t = songbird_proto::auth::transcript("chat.example", &[0x11; 32], &dev(0x22), 1).unwrap();
    let want = unhex(
        "736f6e67626972642e76312f6465766963652d6175746800 0c 636861742e6578616d706c65 \
         1111111111111111111111111111111111111111111111111111111111111111 \
         22222222222222222222222222222222 00000001",
    );
    assert_eq!(Bytes::from(t), want);
}
