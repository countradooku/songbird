//! The backup wizard: why → where → recovery key → how often → done.
//! Shown pushed from the backup settings, and inline in onboarding (which
//! has just confirmed the recovery key, so that step is skipped there).

use std::rc::Rc;

use nsh_core::prelude::*;

use super::{FlowHost, dest_fields, dest_group, dest_ready, destinations};
use crate::{
    store::{
        BackupDestination,
        ext_onboarding::{Frequency, key_last_group_matches},
        store,
    },
    ui::*,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Why,
    Where,
    Key,
    Options,
    Done,
}

/// The wizard as one element (its steps inside). `skip_key`: the user just
/// confirmed the recovery key. `on_done` leaves it. With a `host`, the
/// host's Back steps through the pages and the wizard draws none of its own.
pub(crate) fn wizard_body(
    skip_key: bool,
    on_done: Rc<dyn Fn()>,
    host: Option<FlowHost>,
) -> AnyElement {
    let s = store();
    // Onboarding has just asked "Back up your chats?", so its wizard
    // starts at the destination: no second intro.
    let page = signal(if skip_key { Page::Where } else { Page::Why });
    let forward = stored(true);
    let dest = signal(BackupDestination::SongbirdServers);
    let media = signal(true);
    let freq = signal(Frequency::Daily);
    let typed = signal(String::new());
    let go = move |p: Page, fwd: bool| {
        forward.with(|f| *f = fwd);
        page.set(p);
    };
    let previous = move |p: Page| match p {
        Page::Why | Page::Done => None,
        Page::Where => (!skip_key).then_some(Page::Why),
        Page::Key => Some(Page::Where),
        Page::Options => Some(if skip_key { Page::Where } else { Page::Key }),
    };
    if let Some(h) = host {
        h.back.replace(Some(Rc::new(move || {
            match previous(page.get_untracked()) {
                Some(p) => {
                    go(p, false);
                    true
                }
                None => false,
            }
        })));
    }
    // The wizard's own Back, only when no host draws one.
    let back_btn = move |p: Page| {
        previous(p)
            .filter(|_| host.is_none())
            .map(|to| btn("Back", Variant::Ghost, BtnSize::Md, move || go(to, false)).w_full())
    };
    view()
        .flex_1()
        .child(dynamic(move || {
            let p = page.get();
            let on_done = on_done.clone();
            untracked(move || {
                if let Some(h) = host {
                    h.hide_back.set(p == Page::Done);
                }
                let dir = if forward.get() { 1.0 } else { -1.0 };
                let enter = motion().entering(
                    MotionSpec::new(KeyframeTiming::new(motion::BASE).easing(Easing::EaseOut))
                        .values(MotionChannel::Opacity, [0.0, 1.0])
                        .values(MotionChannel::TranslateX, [24.0 * dir, 0.0]),
                );
                let body = match p {
                    Page::Why => flow_layout(
                        view()
                            .gap_4()
                            .child(hero_icon(Icon::Cloud))
                            .child(flow_title("Back up your chats"))
                            .child(flow_lead(if is_desktop() {
                                "If you lose or replace a device, a backup brings your messages back. It's encrypted with your recovery key, so only you can open it."
                            } else {
                                "If you lose or replace your phone, a backup brings your messages back. It's encrypted with your recovery key, so only you can open it."
                            })),
                        view()
                            .child(btn("Continue", Variant::Primary, BtnSize::Lg, move || go(Page::Where, true)).w_full()),
                    ),
                    Page::Where => flow_layout(
                        view()
                            .gap_4()
                            .child(flow_title("Where should backups go?"))
                            .child(flow_lead("Wherever you choose, the backup is encrypted on this device first."))
                            .child(dest_group(destinations(), move || Some(dest.get()), move |d| dest.set(d)).mx_0())
                            .child(dynamic(move || {
                                let d = dest.get();
                                untracked(move || dest_fields(s, d).map(|f| f.into_element()).unwrap_or_else(|| view().into_element()))
                            })),
                        view()
                            .gap_2()
                            .child(
                                btn("Continue", Variant::Primary, BtnSize::Lg, move || {
                                    go(if skip_key { Page::Options } else { Page::Key }, true)
                                })
                                .w_full()
                                .disabled(move || !dest_ready(s, dest.get())),
                            )
                            .child(back_btn(Page::Where)),
                    ),
                    Page::Key => {
                        let key = s.session.with_untracked(|x| x.recovery_key.clone());
                        let k2 = key.clone();
                        let ok = computed(move || key_last_group_matches(&key, &typed.get()));
                        let ok = move || ok.get();
                        let full = move || typed.with(|t| t.trim().len() >= 4);
                        flow_layout(
                            view()
                                .gap_4()
                                .child(hero_icon(Icon::Key))
                                .child(flow_title("Confirm your recovery key"))
                                .child(flow_lead(
                                    "Backups are locked with your recovery key. Type its last group of four to show you still have it.",
                                ))
                                .child(labelled_field(
                                    "Last group of your recovery key",
                                    field("Last 4 characters", typed)
                                        .max_length(4)
                                        .font_family(MONO)
                                        .auto_capitalize(AutoCapitalize::Characters)
                                        .auto_correct(false)
                                        .auto_focus(true)
                                        .on_submit(move |_: &str| {
                                            if key_last_group_matches(&k2, &typed.get_untracked()) {
                                                go(Page::Options, true);
                                            }
                                        }),
                                    "",
                                    || false,
                                ))
                                .child(status_line(
                                    move || match (full(), ok()) {
                                        (false, _) => StatusTone::Muted,
                                        (true, true) => StatusTone::Good,
                                        (true, false) => StatusTone::Problem,
                                    },
                                    move || match (full(), ok()) {
                                        (false, _) => Icon::Key,
                                        (true, true) => Icon::Check,
                                        (true, false) => Icon::Alert,
                                    },
                                    move || match (full(), ok()) {
                                        (false, _) => "It's the last block on your recovery sheet.".into(),
                                        (true, true) => "That's right.".into(),
                                        (true, false) => "That doesn't match. Check the last block of your key.".into(),
                                    },
                                )),
                            view()
                                .gap_2()
                                .child(
                                    btn("Continue", Variant::Primary, BtnSize::Lg, move || go(Page::Options, true))
                                        .w_full()
                                        .disabled(move || !ok()),
                                )
                                .child(back_btn(Page::Key)),
                        )
                    }
                    Page::Options => flow_layout(
                        view()
                            .gap_4()
                            .child(flow_title("How often?"))
                            .child(flow_lead(if is_desktop() {
                                "Backups run in the background while Songbird is open."
                            } else {
                                "Backups run in the background while your phone charges on Wi\u{2011}Fi."
                            }))
                            .child(segmented(
                                vec![(Frequency::Daily, "Daily"), (Frequency::Weekly, "Weekly"), (Frequency::Monthly, "Monthly")],
                                move || freq.get(),
                                move |f| freq.set(f),
                            ))
                            .child(
                                group([toggle_row(
                                    "Include photos and videos",
                                    Some("Backups are bigger with media."),
                                    move || media.get(),
                                    move |v| media.set(v),
                                )])
                                .mx_0(),
                            ),
                        view()
                            .gap_2()
                            .child(
                                btn("Turn on backups", Variant::Primary, BtnSize::Lg, move || {
                                    s.enable_backups(dest.get_untracked(), media.get_untracked(), freq.get_untracked());
                                    go(Page::Done, true);
                                })
                                .w_full(),
                            )
                            .child(back_btn(Page::Options)),
                    ),
                    Page::Done => {
                        let on_done = on_done.clone();
                        flow_layout(
                            view()
                                .gap_4()
                                .child(hero_icon(Icon::ShieldCheck))
                                .child(flow_title("Backups are on"))
                                .child(flow_lead(move || {
                                    format!(
                                        "Your first backup to {} is running now. After that, Songbird backs up {}.",
                                        dest.get().label(),
                                        freq.get().label().to_lowercase()
                                    )
                                })),
                            view().child(btn("Done", Variant::Primary, BtnSize::Lg, move || on_done()).w_full()),
                        )
                    }
                };
                view().flex_1().bind_motion(&enter).child(body).into_element()
            })
        }))
        .into_element()
}
