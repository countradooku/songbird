//! "Transfer chat history to a new phone": both phones on one network,
//! paired by a code one shows and the other scans, then a direct,
//! encrypted copy.

use std::time::Duration;

use nsh_core::prelude::*;

use crate::{
    nav,
    store::{
        ext_onboarding::{BACKUP_CHATS, BACKUP_MESSAGES, TransferStage, pairing_code, thousands},
        store,
    },
    ui::*,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Intro,
    /// This is the old phone: it scans the new one's code.
    Old,
    /// This is the new phone: it shows its code.
    New,
    Pairing,
    Moving,
    Done,
}

pub(super) fn transfer_body() -> AnyElement {
    let s = store();
    let stage = s.transfer_stage();
    let role = signal(None::<bool>);
    let screen = computed(move || match stage.get() {
        TransferStage::Idle => match role.get() {
            None => Screen::Intro,
            Some(true) => Screen::Old,
            Some(false) => Screen::New,
        },
        TransferStage::Pairing => Screen::Pairing,
        TransferStage::Moving(_) => Screen::Moving,
        TransferStage::Done => Screen::Done,
    });
    let moved = move || match stage.get() {
        TransferStage::Moving(p) => p,
        TransferStage::Done => 1.0,
        _ => 0.0,
    };
    view()
        .flex_1()
        .child(dynamic(move || {
            let sc = screen.get();
            untracked(move || {
                let enter = motion().entering(
                    MotionSpec::new(KeyframeTiming::new(motion::BASE).easing(Easing::EaseOut))
                        .values(MotionChannel::Opacity, [0.0, 1.0])
                        .values(MotionChannel::TranslateX, [24.0, 0.0]),
                );
                let body = match sc {
                    Screen::Intro => flow_layout(
                        view()
                            .gap_4()
                            .child(hero_icon(Icon::Smartphone))
                            .child(flow_title("Move your chats to a new phone"))
                            .child(flow_lead(
                                "Your chats go straight from one phone to the other over your Wi\u{2011}Fi, encrypted. Nothing goes through Songbird's servers.",
                            ))
                            .child(
                                view()
                                    .gap_3()
                                    .child(numbered_step(1, "Keep both phones on the same Wi\u{2011}Fi, close to each other."))
                                    .child(numbered_step(2, "Open Songbird on both, and come to this screen on each."))
                                    .child(numbered_step(3, "Scan the code your new phone shows with your old phone.")),
                            ),
                        view()
                            .gap_2()
                            .child(btn("This is my old phone", Variant::Primary, BtnSize::Lg, move || role.set(Some(true))).w_full())
                            .child(btn("This is my new phone", Variant::Secondary, BtnSize::Lg, move || role.set(Some(false))).w_full()),
                    ),
                    Screen::Old => {
                        // mock: the camera finds the new phone's code after a moment.
                        set_timeout(Duration::from_millis(2600), move || {
                            if role.try_get() == Some(Some(true)) {
                                s.start_transfer();
                            }
                        });
                        flow_layout(
                            view()
                                .gap_4()
                                .child(flow_title("Scan your new phone's code"))
                                .child(scanner(240.0, "Point this phone at the code on your new phone.")),
                            view().child(btn("Back", Variant::Ghost, BtnSize::Md, move || role.set(None)).w_full()),
                        )
                    }
                    Screen::New => {
                        // mock: the old phone scans this code after a moment.
                        set_timeout(Duration::from_millis(3200), move || {
                            if role.try_get() == Some(Some(false)) {
                                s.start_transfer();
                            }
                        });
                        let code = pairing_code("transfer-new-phone");
                        flow_layout(
                            view()
                                .gap_4()
                                .child(flow_title("Scan this code with your old phone"))
                                .child(flow_lead("On your old phone, open Songbird → You → Chats → Backups → Transfer to a new phone."))
                                .child(
                                    view()
                                        .role(AccessibilityRole::Image)
                                        .label("Transfer code for your old phone to scan")
                                        .child(qr_code("transfer-new-phone", 200.0)),
                                )
                                .child(muted("Can't scan? Type this code on your old phone.").text_center())
                                .child(numeric_code(code)),
                            view().child(btn("Back", Variant::Ghost, BtnSize::Md, move || role.set(None)).w_full()),
                        )
                    }
                    Screen::Pairing => flow_layout(
                        view()
                            .gap_4()
                            .child(flow_title("Connecting your phones…"))
                            .child(flow_lead("Checking that both phones show the same code, so no one else can join."))
                            .child(busy_bar("Connecting")),
                        view(),
                    ),
                    Screen::Moving => flow_layout(
                        view()
                            .gap_4()
                            .child(flow_title("Transferring your chats"))
                            .child(flow_lead("Keep both phones open and close together."))
                            .child(progress_bar("Transferring", moved))
                            .child(muted(move || {
                                let n = (moved() * BACKUP_MESSAGES as f32).round() as u32;
                                format!("{} of {} messages", thousands(n), thousands(BACKUP_MESSAGES))
                            })),
                        view(),
                    ),
                    Screen::Done => flow_layout(
                        view()
                            .gap_4()
                            .child(hero_icon(Icon::ShieldCheck))
                            .child(flow_title("Transfer complete"))
                            .child(flow_lead(format!(
                                "{} messages in {} chats are on your new phone. You can keep using this phone as a linked device, or log it out.",
                                thousands(BACKUP_MESSAGES),
                                BACKUP_CHATS
                            ))),
                        view().child(
                            btn("Done", Variant::Primary, BtnSize::Lg, move || {
                                s.reset_transfer();
                                role.set(None);
                                nav::pop();
                            })
                            .w_full(),
                        ),
                    ),
                };
                view().flex_1().bind_motion(&enter).child(body).into_element()
            })
        }))
        .into_element()
}
