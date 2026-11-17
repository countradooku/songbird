//! The ui layer gallery: every component in every variant, size and
//! state, the icon set and the colour tokens with their contrast, in the
//! current appearance (Design Guides, "Show it"). How the owner reviews
//! the design system.

use nsh_core::prelude::*;

use crate::{
    features::{plans, whatsapp},
    nav,
    ui::*,
};

/// Every glyph of [`Icon`], in its declaration order.
pub const ALL_ICONS: [Icon; 110] = {
    use Icon::*;
    [
        Chats, Calls, Communities, You, Search, Plus, Close, Back, Forward, ChevronRight, ChevronDown, More,
        MoreHorizontal, Send, Mic, MicOff, Camera, Video, VideoOff, Phone, PhoneIncoming, PhoneOutgoing,
        PhoneMissed, PhoneOff, Paperclip, Smile, Image, File, MapPin, Contact, Poll, Calendar, Sticker, Lock,
        Unlock, Shield, ShieldCheck, Key, Eye, EyeOff, Bell, BellOff, Pin, Archive, Star, Trash, Edit, Copy,
        Reply, Share, Link, QrCode, Scan, Users, UserPlus, User, Settings, Info, Alert, Check, Clock, Timer,
        Download, Upload, Cloud, HardDrive, Smartphone, Laptop, Globe, Palette, HelpCircle, Heart, Gift,
        Sparkles, Speaker, ScreenShare, Hand, Grid, Filter, Play, Pause, Megaphone, Flag, Ban, Database, Wifi,
        WifiOff, Moon, Sun, Zap, Refresh, LogOut, Sliders, Volume, Minimize, Maximize, Keyboard, Feather,
        Inbox, Layers, Baby, Server, Tablet, FlipCamera, SpeakerView, ChevronUp, ZoomIn, ZoomOut, Compose, ArrowLeft,
    ]
};

/// Fails to compile when a glyph is added to `Icon` and not to
/// [`ALL_ICONS`] (add it to both).
#[allow(dead_code)]
fn every_icon_is_listed(i: Icon) {
    use Icon::*;
    match i {
        Chats | Calls | Communities | You | Search | Plus | Close | Back | Forward | ChevronRight | ChevronDown
        | More | MoreHorizontal | Send | Mic | MicOff | Camera | Video | VideoOff | Phone | PhoneIncoming
        | PhoneOutgoing | PhoneMissed | PhoneOff | Paperclip | Smile | Image | File | MapPin | Contact | Poll
        | Calendar | Sticker | Lock | Unlock | Shield | ShieldCheck | Key | Eye | EyeOff | Bell | BellOff | Pin
        | Archive | Star | Trash | Edit | Copy | Reply | Share | Link | QrCode | Scan | Users | UserPlus | User
        | Settings | Info | Alert | Check | Clock | Timer | Download | Upload | Cloud | HardDrive | Smartphone
        | Laptop | Globe | Palette | HelpCircle | Heart | Gift | Sparkles | Speaker | ScreenShare | Hand | Grid
        | Filter | Play | Pause | Megaphone | Flag | Ban | Database | Wifi | WifiOff | Moon | Sun | Zap
        | Refresh | LogOut | Sliders | Volume | Minimize | Maximize | Keyboard | Feather | Inbox | Layers
        | Baby | Server | Tablet | FlipCamera | SpeakerView | ChevronUp | ZoomIn | ZoomOut | Compose | ArrowLeft => {}
    }
}

/// A colour role, the ink drawn on it, and their names.
type Pair = (&'static str, fn() -> AdaptiveColor, fn() -> AdaptiveColor);

const SWATCHES: &[Pair] = &[
    ("background", c::background, c::foreground),
    ("card", c::card, c::foreground),
    ("popover", c::popover, c::foreground),
    ("primary", c::primary, c::on_primary),
    ("secondary", c::secondary, c::on_secondary),
    ("muted", c::muted, c::muted_fg),
    ("accent", c::accent, c::on_accent),
    ("destructive", c::destructive, c::on_destructive),
    ("sidebar", c::sidebar, c::foreground),
    ("chat-bg", c::chat_bg, c::foreground),
    ("bubble-out", c::bubble_out, c::on_bubble_out),
    ("bubble-in", c::bubble_in, c::on_bubble_in),
    ("bubble-meta on bubble-in", c::bubble_in, c::bubble_meta),
    ("link on background", c::background, c::link),
    ("tick-read on bubble-out", c::bubble_out, c::tick_read),
    ("success", c::success, c::on_success),
    ("warning on warning-bg", c::warning_bg, c::warning),
    ("foreground on info-bg", c::info_bg, c::foreground),
    ("foreground on danger-bg", c::danger_bg, c::foreground),
    ("destructive on danger-bg", c::danger_bg, c::destructive),
    ("whatsapp on background", c::background, c::whatsapp),
    ("call-bg", c::call_bg, c::on_call),
    ("call-accept", c::call_accept, c::on_call),
    ("call-decline", c::call_decline, c::on_call),
    ("highlight", c::highlight, c::foreground),
    ("online on background", c::background, c::online),
    ("border on background", c::background, c::border),
];

/// WCAG relative luminance of an sRGB colour.
pub fn luminance(r: f32, g: f32, b: f32) -> f32 {
    let lin = |v: f32| if v <= 0.040_45 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) };
    0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

/// WCAG contrast ratio of two opaque colours (1 to 21).
pub fn contrast(a: (f32, f32, f32), b: (f32, f32, f32)) -> f32 {
    let (la, lb) = (luminance(a.0, a.1, a.2), luminance(b.0, b.1, b.2));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

fn rgb(h: Hsla) -> (f32, f32, f32) {
    let c = Rgba::from(h);
    (c.r, c.g, c.b)
}

/// "7.1:1 AAA", with the level in words so it never relies on colour.
fn ratio_label(ratio: f32) -> String {
    let level = if ratio >= 7.0 {
        "AAA"
    } else if ratio >= 4.5 {
        "AA"
    } else if ratio >= 3.0 {
        "AA large and UI"
    } else {
        "decorative only"
    };
    format!("{ratio:.1}:1 {level}")
}

/// The gallery, pushed (You → Help → Design system).
pub fn ui_gallery() {
    nav::push("gallery", gallery_page);
}

fn gallery_page() -> Screen {
    let sheet_open = signal(false);
    let body = view()
        .w_full()
        .max_w(px(1040.0))
        .self_center()
        .child(view().px_4().pt_4().child(muted(
            "Every component of Songbird's ui layer in each variant, size and state, as it looks in the current appearance. Switch light and dark in You → Appearance to compare.",
        )))
        .child(skins())
        .child(buttons())
        .child(selection())
        .child(inputs())
        .child(rows())
        .child(people())
        .child(status())
        .child(surfaces())
        .child(overlays(sheet_open))
        .child(extras())
        .child(type_and_shape())
        .child(icons())
        .child(swatches());
    page(
        "Design system",
        view()
            .flex_1()
            .child(page_scroll(body))
            .child(app_sheet(
                sheet_open,
                "A sheet",
                view()
                    .px_4()
                    .pb_2()
                    .gap_3()
                    .child(body_text("Sheets hold supplementary work. A bottom sheet on phones, a centred panel on desktops."))
                    .child(btn("Done", Variant::Primary, BtnSize::Lg, move || sheet_open.set(false)))
                    .child(btn("Not now", Variant::Secondary, BtnSize::Lg, move || sheet_open.set(false))),
            )),
    )
}

fn body_text(s: &'static str) -> Text {
    body(s)
}

/// A titled section of the gallery.
fn section(title: &'static str, content: impl IntoElement) -> View {
    view().child(section_title(title)).child(view().px_4().gap_3().child(content))
}

/// A caption under an item.
fn labelled(label: impl Into<SharedString>, item: impl IntoElement) -> View {
    view()
        .items_start()
        .gap_1()
        .child(item)
        .child(
            text(label.into())
                .text_size(px(font::CAPTION))
                .text_color(move || c::muted_fg()),
        )
}

/// A wrapping row of items.
fn line() -> View {
    view().flex_row().flex_wrap().items_end().gap_4()
}

/// Debug builds: the skin the app draws with (a switcher, so this Mac can
/// preview every platform), and each skin's components side by side.
/// The previews take their shapes, sizes and type from their skin; colours
/// are the app's current skin's (one theme is live at a time).
fn skins() -> View {
    if !cfg!(debug_assertions) {
        return view();
    }
    let current = signal(skin());
    let preview = |k: Skin| {
        with_skin(k, move || {
            let on = signal(true);
            let off = signal(false);
            let seg = signal(0_u8);
            let q = signal(String::new());
            let sp = spec();
            view()
                .w(px(248.0))
                .gap_3()
                .p_3()
                .rounded(px(sp.radius.card))
                .bg(move || c::background())
                .border(hairline())
                .border_color(move || c::border())
                .child(text(k.label()).text_size(px(sp.page_title.size)).font_weight(sp.page_title.weight).role(AccessibilityRole::Header))
                .child(
                    view()
                        .flex_row()
                        .gap_2()
                        .child(btn("Send", Variant::Primary, BtnSize::Md, || toast("Pressed")))
                        .child(btn("Later", Variant::Secondary, BtnSize::Md, || toast("Pressed"))),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .child(toggle(format!("{} on", k.label()), move || on.get(), move |v| on.set(v)))
                        .child(toggle(format!("{} off", k.label()), move || off.get(), move |v| off.set(v)))
                        .child(icon_btn(Icon::More, "More", || {}))
                        .child(sp.fab.then(|| fab(Icon::Plus, "New chat", || {}))),
                )
                .child(
                    view()
                        .flex_row()
                        .gap_2()
                        .child(chip("Unread", || true, || {}))
                        .child(chip("Groups", || false, || {})),
                )
                .child(segmented(vec![(0_u8, "Day"), (1, "Week")], move || seg.get(), move |v| seg.set(v)))
                .child(search_field("Search", q))
                .child(
                    view().mx(px(-16.0)).child(group(vec![
                        Row::new("Privacy").icon(Icon::Lock).chevron().on_press(|| {}).build(),
                        toggle_row_icon(Icon::Bell, "Alerts", None, move || on.get(), move |v| on.set(v)),
                    ])),
                )
        })
    };
    section(
        "Platform skin (debug)",
        view()
            .gap_3()
            .child(muted(
                "Songbird follows each platform's design language: Apple on iOS and macOS, Material on Android and the web, Fluent on Windows, Adwaita on Linux. Choose one to draw the whole app with it (⌘⌥S cycles).",
            ))
            .child(view().max_w(px(440.0)).child(segmented(
                Skin::ALL.into_iter().map(|k| (k, k.label())).collect(),
                move || current.get(),
                move |k| {
                    current.set(k);
                    crate::ui::skin::set_skin(k);
                },
            )))
            .child(view().flex_row().flex_wrap().gap_3().children(Skin::ALL.map(preview))),
    )
}

fn buttons() -> View {
    let variants = [
        (Variant::Primary, "Primary"),
        (Variant::Secondary, "Secondary"),
        (Variant::Outline, "Outline"),
        (Variant::Ghost, "Ghost"),
        (Variant::Danger, "Danger"),
    ];
    let sizes = [(BtnSize::Sm, "small"), (BtnSize::Md, "medium"), (BtnSize::Lg, "large")];
    section(
        "Buttons",
        view()
            .gap_4()
            .children(variants.into_iter().map(move |(v, name)| {
                line()
                    .children(sizes.into_iter().map(move |(sz, sname)| {
                        labelled(format!("{name} · {sname}"), btn(name, v, sz, || toast("Pressed")))
                    }))
                    .child(labelled(
                        format!("{name} · with icon"),
                        btn_with_icon(name, Some(Icon::Send), v, BtnSize::Md, || toast("Pressed")),
                    ))
                    .child(labelled(format!("{name} · disabled"), btn(name, v, BtnSize::Md, || {}).disabled(true)))
            }))
            .child(
                line()
                    .child(labelled("Icon button", icon_btn(Icon::Search, "Search", || toast("Search"))))
                    .child(labelled("Icon button", icon_btn(Icon::More, "More", || toast("More"))))
                    .child(labelled("Icon button · disabled", icon_btn(Icon::Trash, "Delete", || {}).disabled(true)))
                    .child(labelled("Floating button", fab(Icon::Plus, "New chat", || toast("New chat"))))
                    .child(labelled(
                        "Floating button · over a list",
                        view()
                            .w(px(200.0))
                            .h(px(120.0))
                            .rounded(move || radius::lg())
                            .bg(move || c::card())
                            .border(hairline())
                            .border_color(move || c::border())
                            .child(view().absolute().right(px(16.0)).bottom(px(16.0)).child(fab(Icon::Plus, "New chat (floating)", || toast("New chat")))),
                    )),
            ),
    )
}

fn selection() -> View {
    let chip_on = signal(true);
    let chip_off = signal(false);
    let seg = signal(1_u8);
    let t_on = signal(true);
    let t_off = signal(false);
    section(
        "Selection",
        view()
            .gap_4()
            .child(
                line()
                    .child(labelled("Chip · selected", chip("Unread", move || chip_on.get(), move || chip_on.update(|v| *v = !*v))))
                    .child(labelled("Chip · not selected", chip("Groups", move || chip_off.get(), move || chip_off.update(|v| *v = !*v)))),
            )
            .child(labelled(
                "Chip strip · fades at the end",
                view().mx(px(-16.0)).w(px(340.0)).child(chip_scroller(
                    ["All", "Unread", "Favourites", "Groups", "Channels", "Work"].into_iter().enumerate().map(move |(i, l)| {
                        chip(l, move || i == 0, || {}).into_element()
                    }),
                    c::background,
                )),
            ))
            .child(labelled(
                "Segmented control",
                view().w(px(320.0)).child(segmented(
                    vec![(0_u8, "Day"), (1, "Week"), (2, "Month")],
                    move || seg.get(),
                    move |v| seg.set(v),
                )),
            ))
            .child(
                line()
                    .child(labelled("Toggle · on", toggle("On", move || t_on.get(), move |v| t_on.set(v))))
                    .child(labelled("Toggle · off", toggle("Off", move || t_off.get(), move |v| t_off.set(v))))
                    .child(labelled("Toggle · disabled on", toggle("Disabled", || true, |_| {}).disabled(true)))
                    .child(labelled("Toggle · disabled off", toggle("Disabled", || false, |_| {}).disabled(true))),
            ),
    )
}

fn inputs() -> View {
    let name = signal("Ana".to_string());
    let bad = signal("an".to_string());
    let query = signal(String::new());
    section(
        "Inputs",
        view()
            .gap_4()
            .max_w(px(420.0))
            .child(labelled_field("Name", field("Your name", name), "Shown to your contacts.", || false))
            .child(labelled_field(
                "Username",
                field("Username", bad),
                "At least 3 characters.",
                move || bad.with(|b| b.len() < 3),
            ))
            .child(labelled("Search field", search_field("Search", query))),
    )
}

fn rows() -> View {
    let on = signal(true);
    let on_icon = signal(false);
    let caption = |s: &'static str| {
        text(s).text_size(px(font::CAPTION)).text_color(move || c::muted_fg()).px_4().pt_2()
    };
    section(
        "Rows and groups",
        view()
            .mx(px(-16.0))
            .max_w(px(560.0))
            .gap_2()
            .child(caption("Rows with icon tiles: separators start under the titles"))
            .child(group([
                Row::new("With icon and subtitle").icon(Icon::Bell).subtitle("A short explanation").build(),
                Row::new("Chevron").icon(Icon::Lock).chevron().on_press(|| toast("Row pressed")).build(),
                Row::new("Value").icon(Icon::Globe).value("English").on_press(|| toast("Row pressed")).build(),
                Row::new("Element").icon(Icon::Star).trailing(tag("New")).build(),
                toggle_row_icon(Icon::Moon, "Toggle row with icon", None, move || on_icon.get(), move |v| on_icon.set(v)),
                toggle_row_with(Some(Icon::Bell), "Toggle row · disabled", Some("Turned off by Do not disturb"), || true, |_| {}, || true),
                Row::new("Danger").icon(Icon::Trash).danger().on_press(|| toast("Row pressed")).build(),
            ]))
            .child(caption("Rows without a leading icon"))
            .child(group_plain([
                Row::new("Plain row").build(),
                Row::new("Plain row with value").value("Off").on_press(|| toast("Row pressed")).build(),
                toggle_row("Toggle row", Some("Subtitle of a toggle row"), move || on.get(), move |v| on.set(v)),
                toggle_row_with(None, "Toggle row · disabled off", None, || false, |_| {}, || true),
            ]))
            .child(caption("People: separators start under the names"))
            .child(group_with_inset(
                [
                    Row::new("Ana Popescu")
                        .leading(avatar_presence_on("Ana Popescu", 1, 36.0, || true, c::card))
                        .subtitle("online")
                        .on_press(|| toast("Row pressed"))
                        .build(),
                    Row::new("Mama").leading(avatar("Mama", 5, 36.0)).subtitle("last seen today at 08:26").chevron().build(),
                ],
                INSET_AVATAR,
            )),
    )
}

fn people() -> View {
    section(
        "People",
        line()
            .child(labelled("24", avatar("Ana Popescu", 1, 24.0)))
            .child(labelled("36", avatar("Mihai Ionescu", 2, 36.0)))
            .child(labelled("48", avatar("Ioana Dobre", 3, 48.0)))
            .child(labelled("64", avatar("Tomás Silva", 4, 64.0)))
            .children((5..9).map(|seed| labelled(format!("Contact {}", seed - 4), avatar("Songbird User", seed, 40.0))))
            .child(labelled("You", avatar("Radu", portrait::ME_SEED, 48.0)))
            .child(labelled("Online", avatar_presence("Ana Popescu", 1, 48.0, || true)))
            .child(labelled("Online · 36", avatar_presence("Mihai Ionescu", 2, 36.0, || true)))
            .child(labelled("Offline", avatar_presence("Ana Popescu", 1, 48.0, || false))),
    )
}

fn status() -> View {
    let ticks_all = [Tick::Sending, Tick::Sent, Tick::Delivered, Tick::Read, Tick::Played, Tick::Failed];
    section(
        "Status",
        view()
            .gap_4()
            .child(
                line()
                    .child(labelled("Unread", unread_badge(|| 3, || false)))
                    .child(labelled("Unread · muted", unread_badge(|| 12, || true)))
                    .child(labelled("Unread · large", unread_badge(|| 1204, || false)))
                    .child(labelled(
                        "Unread · on an icon",
                        view()
                            .w(px(56.0))
                            .h(px(30.0))
                            .rounded_full()
                            .items_center()
                            .justify_center()
                            .bg(move || c::accent())
                            .text_color(move || c::primary())
                            .child(icon(Icon::Chats, 22.0))
                            .child(view().absolute().left(px(31.0)).top(px(-8.0)).w(px(48.0)).items_start().child(unread_badge_on(|| 11, c::background))),
                    ))
                    .child(labelled("Tag", tag("Admin")))
                    .child(labelled("Tag", tag("Plus"))),
            )
            .child(
                line().children(ticks_all.into_iter().map(|t| {
                    labelled(
                        t.label(),
                        view().p_2().rounded(move || radius::sm()).bg(move || c::bubble_out()).child(ticks(move || t)),
                    )
                })),
            )
            .child(
                view()
                    .gap_2()
                    .max_w(px(520.0))
                    .child(banner(Tone::Info, Icon::Info, "Info: you're offline. Messages send when you're back."))
                    .child(banner(Tone::Secure, Icon::Lock, "Secure: messages and calls are end-to-end encrypted."))
                    .child(banner(Tone::Warning, Icon::Alert, "Warning: your backup is more than a week old."))
                    .child(banner(Tone::Danger, Icon::Alert, "Danger: this message wasn't sent. Tap to retry.")),
            ),
    )
}

fn surfaces() -> View {
    section(
        "Surfaces and states",
        view()
            .gap_4()
            .child(
                card()
                    .max_w(px(420.0))
                    .gap_1()
                    .child(text("Card").text_size(px(font::TITLE)).font_weight(FontWeight::SEMIBOLD))
                    .child(muted("Grouped content that is not a list of rows.")),
            )
            .child(
                view()
                    .max_w(px(420.0))
                    .rounded(move || radius::lg())
                    .border_1()
                    .border_color(move || c::border())
                    .child(empty_state(
                        Icon::Inbox,
                        "Empty state",
                        "An icon, a title, one sentence and an optional action.",
                        Some(btn("Action", Variant::Secondary, BtnSize::Md, || toast("Action")).into_element()),
                    )),
            )
            .child(
                labelled(
                    "Skeletons",
                    view()
                        .gap_2()
                        .child(skeleton(220.0, 12.0))
                        .child(skeleton(160.0, 10.0))
                        .child(view().w(px(360.0)).child(skeleton_row())),
                ),
            )
            .child(labelled("Separators", view().w(px(320.0)).gap_3().child(separator()).child(separator_inset(56.0)))),
    )
}

fn overlays(sheet_open: Signal<bool>) -> View {
    section(
        "Overlays",
        line()
            .child(btn("Show toast", Variant::Secondary, BtnSize::Md, || toast("This is a toast")))
            .child(btn("Open sheet…", Variant::Secondary, BtnSize::Md, move || sheet_open.set(true)))
            .child(btn("Confirm…", Variant::Secondary, BtnSize::Md, || {
                confirm("Delete \"Roadmap\"?", "It is removed from this device.", "Delete", || toast("Deleted"))
            }))
            .child(btn("Paywall sheet…", Variant::Secondary, BtnSize::Md, || plans::paywall("Chat themes"))),
    )
}

fn extras() -> View {
    section(
        "Extras",
        view()
            .gap_4()
            .child(
                line()
                    .child(labelled("Link", link("songbird.chat", "https://songbird.chat")))
                    .child(labelled("Key caps", view().flex_row().gap_1().child(key_cap(key_label("mod+k"))).child(key_cap(key_label("mod+shift+u")))))
                    .child(labelled("WhatsApp marker", whatsapp::whatsapp_marker())),
            )
            .child(view().max_w(px(420.0)).gap_2().child(bullet(Icon::Check, c::primary, "Bullet with a check")).child(bullet(Icon::Ban, c::muted_fg, "Bullet with a ban")))
            .child(view().max_w(px(420.0)).child(whatsapp::unsupported_note("Polls")))
            .child(
                line()
                    .child(labelled("Select card · selected", select_card(|| true).w(px(200.0)).child(text("Plus"))))
                    .child(labelled("Select card", select_card(|| false).w(px(200.0)).child(text("Family")))),
            )
            .child(labelled("QR code", qr_code("https://songbird.chat/i/radu", 140.0).label("QR code sample").role(AccessibilityRole::Image)))
            .child(view().mx(px(-16.0)).max_w(px(560.0)).child(plans::announcement_card())),
    )
}

fn type_and_shape() -> View {
    let sizes = [
        ("Display 28", font::DISPLAY, FontWeight::BOLD),
        ("Heading 20", font::HEADING, FontWeight::BOLD),
        ("Title 17", font::TITLE, FontWeight::SEMIBOLD),
        ("Body", font::body(), FontWeight::NORMAL),
        ("Small 13", font::SMALL, FontWeight::NORMAL),
        ("Caption 12", font::CAPTION, FontWeight::NORMAL),
    ];
    let radii: [(&str, fn() -> Points); 5] = [
        ("Small", radius::sm),
        ("Control", radius::control),
        ("Large", radius::lg),
        ("Bubble", radius::bubble),
        ("Sheet", radius::sheet),
    ];
    let motions = [
        ("Instant", motion::INSTANT),
        ("Fast", motion::FAST),
        ("Base", motion::BASE),
        ("Slow", motion::SLOW),
    ];
    section(
        "Type, radius and motion",
        view()
            .gap_4()
            .child(view().gap_2().children(sizes.into_iter().map(|(name, size, weight)| {
                text(name).text_size(px(size)).font_weight(weight)
            })))
            .child(line().children(radii.into_iter().map(|(name, r)| {
                labelled(
                    name,
                    view().size(px(64.0)).rounded(move || r()).bg(move || c::accent()).border_1().border_color(move || c::border()),
                )
            })))
            .child(line().children(motions.into_iter().map(|(name, ms)| {
                let on = signal(false);
                let reduced = motion::reduced();
                labelled(
                    format!("{name} · {ms:.0} ms"),
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(icon_btn(Icon::Play, format!("Play {}", name.to_lowercase()), move || on.update(|v| *v = !*v)))
                        .child(
                            view()
                                .w(px(120.0))
                                .h(px(32.0))
                                .rounded(move || radius::control())
                                .bg(move || c::secondary())
                                .child(
                                    view()
                                        .size(px(24.0))
                                        .m(px(4.0))
                                        .rounded_full()
                                        .bg(move || c::primary())
                                        .translate_x(move || if on.get() && !reduced { px(88.0) } else { px(0.0) })
                                        .opacity(move || if on.get() && reduced { 0.5_f32 } else { 1.0 })
                                        .transition_all()
                                        .duration(ms)
                                        .ease_bezier(motion::SETTLE.0, motion::SETTLE.1, motion::SETTLE.2, motion::SETTLE.3),
                                ),
                        ),
                )
            }))),
    )
}

/// An icon's name in words: "ChevronRight" reads "Chevron right".
fn icon_name(i: Icon) -> String {
    let raw = format!("{i:?}");
    let mut out = String::new();
    for (n, ch) in raw.chars().enumerate() {
        if n > 0 && ch.is_uppercase() {
            out.push(' ');
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn icons() -> View {
    section(
        "Icons",
        view().flex_row().flex_wrap().gap_2().children(ALL_ICONS.into_iter().map(|i| {
            let name = icon_name(i);
            view()
                .w(px(92.0))
                .h(px(72.0))
                .items_center()
                .justify_center()
                .gap_1()
                .rounded(move || radius::sm())
                .bg(move || c::card())
                .border_1()
                .border_color(move || c::border())
                .role(AccessibilityRole::Image)
                .label(name.clone())
                .child(icon(i, 22.0))
                .child(
                    text(name)
                        .text_size(px(11.0))
                        .number_of_lines(1)
                        .text_color(move || c::muted_fg()),
                )
        })),
    )
}

fn swatches() -> View {
    section(
        "Colour tokens and contrast",
        view()
            .gap_3()
            .child(muted("Each role with the ink drawn on it. Ratios are WCAG contrast in light · dark; body text needs AA (4.5:1)."))
            .child(view().flex_row().flex_wrap().gap_3().children(SWATCHES.iter().map(|(name, bg, ink)| {
                let (bg, ink) = (*bg, *ink);
                let light = contrast(rgb(bg().light), rgb(ink().light));
                let dark = contrast(rgb(bg().dark), rgb(ink().dark));
                let label = format!("{name}: light {}, dark {}", ratio_label(light), ratio_label(dark));
                view()
                    .w(px(232.0))
                    .rounded(move || radius::lg())
                    .overflow_hidden()
                    .border_1()
                    .border_color(move || c::border())
                    .bg(move || c::card())
                    .role(AccessibilityRole::Image)
                    .label(label)
                    .child(
                        view()
                            .h(px(64.0))
                            .px_3()
                            .justify_center()
                            .bg(move || bg())
                            .child(text("Aa Songbird").text_size(px(font::TITLE)).font_weight(FontWeight::SEMIBOLD).text_color(move || ink())),
                    )
                    .child(
                        view()
                            .px_3()
                            .py_2()
                            .gap(px(2.0))
                            .child(text(*name).text_size(px(font::SMALL)).font_weight(FontWeight::SEMIBOLD).number_of_lines(1))
                            .child(text(format!("Light {}", ratio_label(light))).text_size(px(font::CAPTION)).tabular_nums().text_color(move || c::muted_fg()))
                            .child(text(format!("Dark {}", ratio_label(dark))).text_size(px(font::CAPTION)).tabular_nums().text_color(move || c::muted_fg())),
                    )
            }))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_matches_wcag() {
        assert!((contrast((0.0, 0.0, 0.0), (1.0, 1.0, 1.0)) - 21.0).abs() < 0.01);
        assert!((contrast((1.0, 1.0, 1.0), (1.0, 1.0, 1.0)) - 1.0).abs() < 0.001);
        // #767676 on white is the classic 4.54:1.
        let g = 0x76 as f32 / 255.0;
        assert!((contrast((g, g, g), (1.0, 1.0, 1.0)) - 4.54).abs() < 0.02);
    }

    #[test]
    fn levels_are_in_words() {
        assert_eq!(ratio_label(7.2), "7.2:1 AAA");
        assert_eq!(ratio_label(4.6), "4.6:1 AA");
        assert_eq!(ratio_label(3.1), "3.1:1 AA large and UI");
        assert_eq!(ratio_label(1.3), "1.3:1 decorative only");
    }

    #[test]
    fn icon_names_are_words() {
        assert_eq!(icon_name(Icon::ChevronRight), "Chevron right");
        assert_eq!(icon_name(Icon::ZoomIn), "Zoom in");
    }

    #[test]
    fn icons_are_unique() {
        for (i, a) in ALL_ICONS.iter().enumerate() {
            assert!(!ALL_ICONS[i + 1..].contains(a), "{a:?} twice");
        }
    }
}

/// Debug builds only: the app's root with an invisible launcher for the
/// extras' screens, so `preview/Screens_extras.test.tsx` can reach pages
/// whose entry rows other features own. Never in release builds.
#[cfg(debug_assertions)]
#[component]
pub fn ExtrasPreview() -> impl IntoElement {
    use crate::{features, shell, store::Store, theming};
    let s = Store::new();
    provide_context(s);
    theming::follow_settings(s);
    features::desktop::install_shortcuts();
    s.finish_onboarding();
    let entries: [(&'static str, fn()); 15] = [
        ("open-plans", plans::subscription),
        ("open-paywall", || plans::paywall("Chat themes")),
        ("open-invites", plans::invites),
        ("open-invite-link", plans::invite_friend),
        ("open-help", plans::help),
        ("open-contact", plans::contact),
        ("open-licences", plans::licences),
        ("open-family", || nav::push("plans-family", plans::family_page)),
        ("open-wa-optin", whatsapp::opt_in),
        ("open-wa-settings", whatsapp::whatsapp_settings),
        ("open-shortcuts", features::desktop::shortcuts_sheet),
        ("open-desktop", features::desktop::desktop_settings),
        ("open-gallery", ui_gallery),
        ("pop", nav::pop),
        ("pop-root", nav::pop_to_root),
    ];
    view()
        .flex_1()
        .bg(move || c::background())
        .text_color(move || c::foreground())
        .child(when(wide, shell::desktop).otherwise(shell::phone))
        .child(features::calls::call_layer())
        .child(toast_layer())
        .child(
            view()
                .absolute()
                .right_0()
                .bottom_0()
                .flex_row()
                .opacity(0.0)
                .children(entries.into_iter().map(|(label, f)| {
                    nsh_base::button().accessibility_label(label).size(px(10.0)).bg(move || c::border()).on_press(move || {
                        nav::pop_to_root();
                        f()
                    })
                })),
        )
}
