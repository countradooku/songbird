//! Restoring a backup: the key (on a new device), the stages with
//! progress, a clear end, and a failure that leaves nothing half done.

use std::rc::Rc;

use nsh_core::prelude::*;

use crate::{
    store::{
        Store,
        ext_onboarding::{
            RestoreStage, format_key_input, key_checks_out, key_well_formed, thousands,
        },
        store,
    },
    ui::*,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    Running,
    Done,
    Failed,
}

fn phase(stage: RestoreStage) -> Phase {
    match stage {
        RestoreStage::Idle => Phase::Start,
        RestoreStage::Finding | RestoreStage::Decrypting | RestoreStage::Restoring(_) => {
            Phase::Running
        }
        RestoreStage::Done => Phase::Done,
        RestoreStage::Failed => Phase::Failed,
    }
}

/// The restore flow as one element. `ask_key`: a new device, which needs
/// the recovery key (in the app, the key is on the device). `on_finish`
/// leaves after success; `start_fresh` is offered after a failure.
pub(crate) fn restore_view(
    ask_key: bool,
    on_finish: Rc<dyn Fn()>,
    start_fresh: Option<Rc<dyn Fn()>>,
    host: Option<super::FlowHost>,
) -> AnyElement {
    let s = store();
    let stage = s.restore_stage();
    let current = computed(move || phase(stage.get()));
    let key = signal(String::new());
    view()
        .flex_1()
        .child(dynamic(move || {
            let p = current.get();
            let on_finish = on_finish.clone();
            let start_fresh = start_fresh.clone();
            untracked(move || {
                // No way back out of a restore that is running or done.
                if let Some(h) = host {
                    h.hide_back.set(matches!(p, Phase::Running | Phase::Done));
                }
                let enter = motion().entering(
                    MotionSpec::new(KeyframeTiming::new(motion::BASE).easing(Easing::EaseOut))
                        .values(MotionChannel::Opacity, [0.0, 1.0])
                        .values(MotionChannel::TranslateY, [8.0, 0.0]),
                );
                let body = match p {
                    Phase::Start => start(s, ask_key, key),
                    Phase::Running => running(stage),
                    Phase::Done => flow_layout(
                        view()
                            .gap_4()
                            .child(hero_icon(Icon::ShieldCheck))
                            .child(flow_title("Your chats are back"))
                            .child(flow_lead(move || {
                                let (m, c) = s.backup_extra().with(|b| (b.messages, b.chats));
                                format!(
                                    "{} messages in {} chats were restored. Photos and videos download as you open them.",
                                    thousands(m),
                                    thousands(c)
                                )
                            })),
                        view().child(
                            btn("Continue", Variant::Primary, BtnSize::Lg, move || {
                                s.reset_restore();
                                on_finish();
                            })
                            .w_full(),
                        ),
                    ),
                    Phase::Failed => flow_layout(
                        view()
                            .gap_4()
                            .child(hero_icon(Icon::Alert))
                            .child(flow_title("This backup can't be restored"))
                            .child(flow_lead(move || {
                                let why = s.backup_extra().with(|b| b.note.clone()).unwrap_or_else(|| {
                                    "It looks damaged, so Songbird stopped.".into()
                                });
                                format!("{why} Nothing was restored: this device is exactly as it was before.")
                            }))
                            .child(muted(
                                "Try again, or choose an older backup. If it keeps happening, the backup may be from another account or changed since it was made.",
                            )),
                        view()
                            .gap_2()
                            .child(btn("Try again", Variant::Primary, BtnSize::Lg, move || s.reset_restore()).w_full())
                            .child(start_fresh.map(|f| {
                                btn("Start without a backup", Variant::Ghost, BtnSize::Md, move || {
                                    s.reset_restore();
                                    f();
                                })
                                .w_full()
                            })),
                    ),
                };
                view().flex_1().bind_motion(&enter).child(body).into_element()
            })
        }))
        .into_element()
}

fn start(s: Store, ask_key: bool, key: Signal<String>) -> View {
    let ready = move || !ask_key || key.with(|k| key_checks_out(k));
    let typo = move || ask_key && key.with(|k| key_well_formed(k) && !key_checks_out(k));
    let go = move || {
        if ready() {
            dismiss_keyboard();
            s.restore_backup_with(ask_key.then(|| key.get_untracked()), false);
        }
    };
    // Debug builds only, for review: mod+alt+d restores a damaged backup.
    // Nothing on screen offers it.
    #[cfg(debug_assertions)]
    on_key("mod+alt+d", move |_| {
        dismiss_keyboard();
        s.restore_backup(true);
    });
    // Debug builds only, for review: mod+alt+b backs this device up to its
    // backup folder and fills in its key, so a real restore can be shown.
    #[cfg(debug_assertions)]
    on_key("mod+alt+b", move |_| {
        let snap = crate::backend::backup::snapshot(s);
        let target = s.backup_extra().get_untracked();
        spawn(async move {
            let _ = crate::backend::backup::back_up(
                crate::store::BackupDestination::EncryptedFile,
                target,
                snap,
                std::sync::Arc::default(),
            )
            .await;
            key.set(format_key_input(&crate::backend::backup::shown_key()));
        });
    });
    let content = view().gap_4().child(hero_icon(Icon::Download));
    let content = if ask_key {
        content
            .child(flow_title("Restore from a backup"))
            .child(flow_lead(
                "Enter your recovery key. It's the 64 characters, in 16 groups of four, you saved when you made your account.",
            ))
            .child(labelled_field(
                "Recovery key",
                field("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-…", key)
                    .on_change(move |t: &str| key.set(format_key_input(t)))
                    .on_submit(move |_: &str| go())
                    .font_family(MONO)
                    .text_size(px(if wide() { font::body() } else { font::SMALL }))
                    .auto_capitalize(AutoCapitalize::Characters)
                    .auto_correct(false)
                    .auto_focus(true),
                move || -> SharedString {
                    if typo() {
                        "That key doesn't check out. Look for a mistyped character.".into()
                    } else {
                        "Spaces and dashes don't matter.".into()
                    }
                },
                typo,
            ))
    } else {
        content
            .child(flow_title("Restore your backup"))
            .child(flow_lead(move || {
                let last = s
                    .settings
                    .with(|x| x.backup_last.clone())
                    .unwrap_or_else(|| "your last backup".into());
                format!(
                    "This brings back the chats from {}. Messages already on this device are kept.",
                    last.to_lowercase()
                )
            }))
    };
    flow_layout(
        content,
        view().gap_2().child(
            btn("Restore", Variant::Primary, BtnSize::Lg, go)
                .w_full()
                .disabled(move || !ready()),
        ),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Done,
    Now,
    Later,
}

fn stage_row(
    label: impl Fn() -> String + 'static,
    mark: impl Fn() -> Mark + Copy + 'static,
) -> View {
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .min_h(px(32.0))
        .child(
            view()
                .size(px(22.0))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || match mark() {
                    Mark::Done => c::primary(),
                    _ => AdaptiveColor::TRANSPARENT,
                })
                .border_2()
                .border_color(move || match mark() {
                    Mark::Later => c::input(),
                    _ => c::primary(),
                })
                .text_color(move || c::on_primary())
                .transition_colors()
                .duration(motion::BASE)
                .accessibility_elements_hidden(true)
                .child(
                    icon(Icon::Check, 13.0)
                        .style_when(move || mark() != Mark::Done, |s| s.hidden()),
                ),
        )
        .child(
            text(label)
                .flex_1()
                .text_size(px(font::body()))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if mark() == Mark::Later {
                        c::muted_fg()
                    } else {
                        c::foreground()
                    }
                }),
        )
        .child(
            text(move || match mark() {
                Mark::Done => "Done",
                Mark::Now => "In progress",
                Mark::Later => "",
            })
            .text_size(px(font::SMALL))
            .text_color(move || c::muted_fg()),
        )
}

fn running(stage: Signal<RestoreStage>) -> View {
    let order = move || match stage.get() {
        RestoreStage::Finding => 0,
        RestoreStage::Decrypting => 1,
        RestoreStage::Restoring(_) => 2,
        RestoreStage::Done => 3,
        _ => 0,
    };
    let mark = move |i: u8| {
        move || match order().cmp(&i) {
            std::cmp::Ordering::Greater => Mark::Done,
            std::cmp::Ordering::Equal => Mark::Now,
            std::cmp::Ordering::Less => Mark::Later,
        }
    };
    flow_layout(
        view()
            .gap_4()
            .child(flow_title("Restoring your chats"))
            .child(flow_lead(
                "Keep Songbird open. This usually takes a minute or two.",
            ))
            .child(progress_bar("Restoring", move || {
                stage
                    .get()
                    .fraction(store().backup_extra().with(|b| b.messages))
            }))
            .child(
                card()
                    .gap_1()
                    .py_3()
                    .child(stage_row(
                        move || {
                            if order() > 0 {
                                "Found your backup".into()
                            } else {
                                "Finding your backup…".into()
                            }
                        },
                        mark(0),
                    ))
                    .child(stage_row(
                        move || {
                            if order() > 1 {
                                "Decrypted".into()
                            } else {
                                "Decrypting…".into()
                            }
                        },
                        mark(1),
                    ))
                    .child(stage_row(
                        move || match stage.get() {
                            RestoreStage::Restoring(n) => {
                                format!("Restored {} messages", thousands(n))
                            }
                            RestoreStage::Done => format!(
                                "Restored {} messages",
                                thousands(store().backup_extra().with(|b| b.messages))
                            ),
                            _ => "Restoring your messages".into(),
                        },
                        mark(2),
                    )),
            ),
        view(),
    )
}
