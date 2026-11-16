//! The test vectors published in `docs/PROTOCOL.md` §13. Changing an encoding fails here first.
#![allow(clippy::unwrap_used, reason = "tests")]

use bytes::Bytes;
use songbird_proto::frame::{
    MlsCommitRef, Recipient, RejectReason, SendFrame, SendHints, SendPayload, SendStatus,
};
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
            ClientFrame::Send(SendFrame::per_device(
                7,
                [0x11; 16],
                vec![
                    Recipient {
                        device: dev(0x22),
                        envelope: Bytes::from_static(b"abc"),
                    },
                    Recipient {
                        device: dev(0x33),
                        envelope: Bytes::from_static(b"z"),
                    },
                ],
            )),
            "01 00000007 11111111111111111111111111111111 00 0002 \
             22222222222222222222222222222222 00000003 616263 \
             33333333333333333333333333333333 00000001 7a",
        ),
        (
            ClientFrame::Send(SendFrame {
                hints: SendHints::default(),
                req_id: 8,
                idempotency_key: [0x11; 16],
                mls: Some(MlsCommitRef {
                    group: [0x44; 16],
                    epoch: 3,
                }),
                payload: SendPayload::Shared {
                    devices: vec![dev(0x22), dev(0x33)],
                    body: Bytes::from_static(b"grp"),
                },
            }),
            "01 00000008 11111111111111111111111111111111 03 \
             44444444444444444444444444444444 0000000000000003 0002 \
             22222222222222222222222222222222 33333333333333333333333333333333 \
             00000003 677270",
        ),
    ];
    for (frame, hex) in cases {
        let want = unhex(hex);
        assert_eq!(frame.to_bytes(), want);
        assert_eq!(ClientFrame::decode(&want, &Limits::DEFAULT).unwrap(), frame);
    }
}

/// Prompt 4 (D-0061, D-0062): a franked, disappearing message request, and a contact's send
/// with its access key.
#[test]
fn send_frames_with_hints() {
    let one = |envelope: &'static [u8]| {
        vec![Recipient {
            device: dev(0x22),
            envelope: Bytes::from_static(envelope),
        }]
    };
    let mut request = SendFrame::per_device(9, [0x11; 16], one(b"abc"));
    request.hints = SendHints {
        access: None,
        request: true,
        commitment: Some([0x55; 32]),
        expire_after_s: Some(3600),
        group: None,
    };
    let mut contact = SendFrame::per_device(10, [0x11; 16], one(b"z"));
    contact.hints.access = Some([0x66; 16]);
    let cases = [
        (
            request,
            "01 00000009 11111111111111111111111111111111 38 \
             5555555555555555555555555555555555555555555555555555555555555555 00000e10 \
             0001 22222222222222222222222222222222 00000003 616263",
        ),
        (
            contact,
            "01 0000000a 11111111111111111111111111111111 04 \
             66666666666666666666666666666666 \
             0001 22222222222222222222222222222222 00000001 7a",
        ),
    ];
    for (frame, hex) in cases {
        let frame = ClientFrame::Send(frame);
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
    let t =
        songbird_proto::auth::transcript("chat.example", &[0x11; 32], &dev(0x22), 1, &[0x33; 32])
            .unwrap();
    let want = unhex(
        "736f6e67626972642e76312f6465766963652d6175746800 0c 636861742e6578616d706c65 \
         1111111111111111111111111111111111111111111111111111111111111111 \
         22222222222222222222222222222222 00000001 \
         3333333333333333333333333333333333333333333333333333333333333333",
    );
    assert_eq!(Bytes::from(t), want);
}

/// Registration (`docs/PROTOCOL.md` §4.1–§4.2, §13).
#[test]
fn registration() {
    use songbird_proto::registration::{
        DEVICE_CONTEXT, IDENTITY_CONTEXT, RegisterRequest, invite, transcript,
    };
    let code: [u8; 15] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    assert_eq!(invite::format(&code), INVITE_TEXT);
    assert_eq!(invite::parse(&INVITE_TEXT.to_lowercase()), Some(code));
    let req = RegisterRequest {
        challenge: [0x11; 51],
        solutions: vec![7, 31],
        invite: Some(code),
        identity_key: [0x22; 32],
        auth_key: [0x33; 32],
        identity_sig: [0x44; 64],
        auth_sig: [0x55; 64],
    };
    assert_eq!(hex::encode(req.encode()), REQUEST.replace(' ', ""));
    let t = transcript(
        IDENTITY_CONTEXT,
        "chat.example",
        &[0x11; 51],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    assert_eq!(hex::encode(&t), IDENTITY_TRANSCRIPT.replace(' ', ""));
    let d = transcript(
        DEVICE_CONTEXT,
        "chat.example",
        &[0x11; 51],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    assert_eq!(&d[..DEVICE_CONTEXT.len()], DEVICE_CONTEXT);
    assert_eq!(&d[DEVICE_CONTEXT.len()..], &t[IDENTITY_CONTEXT.len()..]);
}

const INVITE_TEXT: &str = "000G-40R4-0M30-E209-185G-R38E";
const REQUEST: &str = "01 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 02 000000070000001f 01 000102030405060708090a0b0c0d0e 2222222222222222222222222222222222222222222222222222222222222222 3333333333333333333333333333333333333333333333333333333333333333 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444 55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
const IDENTITY_TRANSCRIPT: &str = "736f6e67626972642e76312f72656769737465722d6964656e7469747900 0c 636861742e6578616d706c65 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 3333333333333333333333333333333333333333333333333333333333333333";
