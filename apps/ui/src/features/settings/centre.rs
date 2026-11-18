//! The privacy centre, "What Songbird can see": what the servers can see
//! and what they never see, in plain words from `docs/THREAT_MODEL.md` §1,
//! then backups, the phone's own backups, notifications, no tracking, and
//! where the data lives. One sentence per item; details one tap away.

use nsh_core::prelude::*;

use super::links;
use crate::{store::store, ui::*};

/// (icon, one sentence, the "Learn more" text).
type Item = (Icon, &'static str, &'static str);

const CAN_SEE: [Item; 10] = [
    (
        Icon::User,
        "Your account ID and username, so people can find you.",
        "Usernames are stored as a code, not as text. Someone who guesses your exact username can still check that it exists, as with any search.",
    ),
    (
        Icon::Smartphone,
        "Your linked devices and their public keys.",
        "Public keys let others start encrypted chats with your devices. They can lock messages for you, never open them.",
    ),
    (
        Icon::Wifi,
        "When your devices connect, and from which IP address.",
        "Kept only in memory while you're connected, never written to logs. A proxy hides your IP address from us.",
    ),
    (
        Icon::Clock,
        "The size and timing of messages waiting for your devices.",
        "Messages are stored locked until your devices fetch them, then deleted. Anything undelivered is deleted after 30 days.",
    ),
    (
        Icon::Users,
        "Which groups your devices are in, and who runs them.",
        "Our servers put changes to a group's members in order, so everyone agrees on who is in it. The group's name, photo and messages stay encrypted.",
    ),
    (
        Icon::Phone,
        "Who is in a call with whom, only while it rings or lasts.",
        "Removed when the call ends. What you say and show is end\u{2011}to\u{2011}end encrypted.",
    ),
    (
        Icon::Settings,
        "How many settings records you have, and when they change.",
        "Your settings and saved contacts are stored encrypted. We see how many records there are, their size and when they're written, never what they say.",
    ),
    (
        Icon::Eye,
        "Which devices a presence update goes to, and when.",
        "Your app sends your presence sealed, only to the contacts you allow. We can't see who sent it or what it says, and we never tell anyone you're online.",
    ),
    (
        Icon::Zap,
        "That a nudge happened between two accounts.",
        "Nudges are limited per pair of people, so we see that one was sent, never what it is. A nudge is never stored, and one to someone offline is lost.",
    ),
    (
        Icon::Users,
        "For a supervised child: a key, the rules we enforce and an end date.",
        "Not who the parent is: the key isn't linked to any account. Rules only the apps enforce, like quiet hours, are encrypted for the two phones.",
    ),
];

const NEVER_SEES: [Item; 10] = [
    (
        Icon::Chats,
        "Your messages.",
        "Only the people in a chat hold the keys to read it.",
    ),
    (
        Icon::Image,
        "Your photos, videos and files.",
        "Each file is locked on your device with its own key before it's uploaded.",
    ),
    (
        Icon::Video,
        "Your voice and video calls.",
        "Calls are encrypted end to end, including group calls.",
    ),
    (
        Icon::User,
        "Your name, photo and about.",
        "Your profile is encrypted. Only the people you allow get its key.",
    ),
    (
        Icon::Communities,
        "Group names, photos and descriptions.",
        "Members share a key for these. Our servers keep only the locked copy.",
    ),
    (
        Icon::Contact,
        "Your contacts.",
        "Saved contacts, their notes and groups sync between your devices encrypted. We never upload your address book.",
    ),
    (
        Icon::Settings,
        "Your settings.",
        "Theme, notifications, who sees your last seen: each is an encrypted record only your devices can read.",
    ),
    (
        Icon::Eye,
        "Whether you're online, and your last seen.",
        "Your app tells only the contacts you allow, encrypted. Invisible sends nothing at all.",
    ),
    (
        Icon::Smile,
        "Your status and its emoji.",
        "A status is inside your encrypted profile, with the time it clears. Fields you share with nobody are left out of it.",
    ),
    (
        Icon::Cloud,
        "What's in your backups.",
        "Backups are locked with your recovery key before they leave your device.",
    ),
];

pub fn privacy_centre() {
    super::push("What Songbird can see", content);
}

fn content() -> AnyElement {
    view()
        .child(
            view()
                .items_center()
                .px_6()
                .pt_6()
                .gap_3()
                .child(hero_icon(Icon::ShieldCheck))
                .child(
                    text("What Songbird can see")
                        .text_size(px(font::HEADING))
                        .font_weight(FontWeight::BOLD)
                        .text_center()
                        .role(AccessibilityRole::Header),
                )
                .child(
                    body("We built Songbird so we can run it without reading your life. Here is exactly what our servers can and can't see.")
                        .text_center()
                        .max_w(px(460.0))
                        .text_color(move || c::muted_fg()),
                ),
        )
        .child(columns())
        .child(topic(
            Icon::Key,
            "How your backups are protected",
            "Backups are locked on your device with a recovery key only you have. Songbird stores the locked copy and can't open it.",
            "Lose the recovery key and nobody can restore the backup, us included. Keep it somewhere safe, like a password manager.",
            Some(("Backup settings", backup_action)),
        ))
        .child(topic(
            Icon::HardDrive,
            "Your phone's own backups",
            "Songbird's chats are left out of iCloud and Google backups of your phone, so they can't be read from there.",
            "Use Songbird's encrypted backup instead: it keeps your chats with a key only you hold.",
            None,
        ))
        .child(topic(
            Icon::Bell,
            "Notifications",
            "Apple and Google only learn that something arrived for your phone. The message is fetched and opened on your device.",
            "The wake-up they deliver carries no name, no text and no chat. Your device fetches the locked message from Songbird and opens it itself.",
            Some(("Notification settings", super::notifications::notifications)),
        ))
        .child(topic(
            Icon::Ban,
            "No ads, no trackers, no analytics",
            "Songbird has no advertising, no tracking code and no usage analytics. Crash reports stay off unless you turn them on.",
            "We're paid by subscriptions, not by your attention. Crash reports, if you allow them, are scrubbed on your device first.",
            None,
        ))
        .child(topic(
            Icon::Globe,
            "Where your data lives",
            "On servers in the European Union, under European privacy law (GDPR).",
            "Our servers and their backups are in Germany and Finland. The little our servers hold is listed above.",
            None,
        ))
        .child(view().pt_4().child(super::foot("This page is written from Songbird's threat model, the document our engineers build against.")))
        .into_element()
}

/// Backups: their settings, or the set-up wizard when there is none.
fn backup_action() {
    if store().settings.with_untracked(|x| x.backup_on) {
        links::backups();
    } else {
        links::backup_wizard();
    }
}

/// The two lists, side by side when there is room.
fn columns() -> AnyElement {
    let can = || {
        list(
            "Songbird's servers can see",
            Icon::Eye,
            Tone::Info,
            &CAN_SEE,
        )
    };
    let never = || {
        list(
            "Songbird never sees",
            Icon::EyeOff,
            Tone::Secure,
            &NEVER_SEES,
        )
    };
    when(wide, move || {
        // Stretched, so the two cards end on one line.
        view()
            .flex_row()
            .items_stretch()
            .gap_3()
            .px_4()
            .pt_6()
            .child(can().flex_1())
            .child(never().flex_1())
    })
    .otherwise(move || view().px_4().pt_6().gap_4().child(can()).child(never()))
    .into_element()
}

fn list(title: &'static str, glyph: Icon, tone: Tone, items: &'static [Item]) -> View {
    card()
        .gap_3()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .size(px(28.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || {
                            if tone == Tone::Secure {
                                c::accent()
                            } else {
                                c::info_bg()
                            }
                        })
                        .text_color(move || {
                            if tone == Tone::Secure {
                                c::primary()
                            } else {
                                c::link()
                            }
                        })
                        .child(icon(glyph, 16.0)),
                )
                .child(
                    text(title)
                        .flex_1()
                        .text_size(px(font::TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .role(AccessibilityRole::Header),
                ),
        )
        // One sentence per item; the details are one link away, once
        // per card, not a "Learn more" under every line.
        .children(items.iter().map(|(g, line, _more)| {
            view()
                .flex_row()
                .items_start()
                .gap_3()
                .child(icon(*g, 18.0).mt(px(2.0)).text_color(move || c::muted_fg()))
                .child(
                    view().flex_1().min_w(px(0.0)).child(
                        text(*line)
                            .text_size(px(font::body()))
                            .line_height(px(font::body() * 1.35)),
                    ),
                )
        }))
        .child(view().flex_grow(1.0))
        .child(
            view().flex_row().child(
                btn("Read the details", Variant::Ghost, BtnSize::Sm, || {
                    crate::features::plans::open_article("can-see")
                })
                .ml(px(-12.0)),
            ),
        )
}

/// A topic under the lists: a heading, one sentence, more on demand,
/// an optional way to act on it.
fn topic(
    glyph: Icon,
    title: &'static str,
    line: &'static str,
    more: &'static str,
    action: Option<(&'static str, fn())>,
) -> View {
    view().px_4().pt_4().child(
        card()
            .flex_row()
            .items_start()
            .gap_3()
            .child(icon_tile(glyph))
            .child(
                view()
                    .flex_1()
                    .min_w(px(0.0))
                    .gap_1()
                    .child(
                        text(title)
                            .text_size(px(font::body()))
                            .font_weight(FontWeight::SEMIBOLD)
                            .role(AccessibilityRole::Header),
                    )
                    .child(muted(line))
                    .child(expander("Learn more", more))
                    .child(action.map(|(label, f)| {
                        view().flex_row().pt_1().child(btn(
                            label,
                            Variant::Outline,
                            BtnSize::Sm,
                            move || f(),
                        ))
                    })),
            ),
    )
}
