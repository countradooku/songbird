//! The two layouts. Phones: a native stack whose root page holds the four
//! tabs (kept mounted, so each keeps its scroll) over a bottom tab bar.
//! Wide windows: a rail of the sections, the section's list pane, and a
//! detail pane with its own stack (the open chat, and what features push).

use nsh_base::{button, nav_page, nav_stack};
use nsh_core::{element::AnyElement, prelude::*};

use crate::{
    features,
    nav::{self, Route, Tab},
    store::store,
    ui::{
        skin::{self, NavChrome, Sidebar},
        *,
    },
};
use nsh_core::platform::Os;

/// The pages pushed over the root, each made when pushed.
fn pushed() -> AnyElement {
    let routes = nav::routes();
    each(
        move || routes.with(|r| r.0.clone()),
        |route: &Route| route.key.clone(),
        |route, depth| {
            let route = route.get_untracked();
            (route.screen)().on_dismiss(move || nav::truncate(depth.get_untracked()))
        },
    )
    .into_element()
}

/// The Chats unread badge over a tab's icon: its leading half over the
/// icon's top-trailing corner, its centre on the icon's top edge, cut out
/// of the bar's `surface` by a ring. `pill` and `icon` are the selection
/// pill's and the glyph's sizes (the glyph is centred in the pill).
fn tab_badge(pill: (f32, f32), icon: f32, surface: fn() -> AdaptiveColor) -> View {
    let s = store();
    let icon_right = (pill.0 + icon) / 2.0;
    let icon_top = (pill.1 - icon) / 2.0;
    // The badge with its 2pt ring is 24pt tall.
    view()
        .absolute()
        .left(px(icon_right - 8.0))
        .top(px(icon_top - 12.0))
        // Wide enough for "999+": an absolute box is otherwise squeezed to
        // what is left of the pill, and the count wraps.
        .w(px(48.0))
        .items_start()
        .style_when(move || s.total_unread() == 0, |st| st.hidden())
        .child(unread_badge_on(move || s.total_unread(), surface))
}

fn glyph(tab: Tab) -> Icon {
    match tab {
        Tab::Chats => Icon::Chats,
        Tab::Calls => Icon::Calls,
        Tab::Communities => Icon::Communities,
        Tab::You => Icon::You,
    }
}

/// One tab's content, made once per layout.
fn tab_content(tab: Tab) -> AnyElement {
    match tab {
        Tab::Chats => features::chats::chats_tab(),
        Tab::Calls => features::calls::calls_tab(),
        Tab::Communities => features::groups::communities_tab(),
        Tab::You => features::settings::you_tab(),
    }
}

/// The four tabs stacked, only the selected one shown.
fn tab_panels() -> View {
    let current = nav::tab();
    view().flex_1().children(Tab::ALL.into_iter().map(move |tab| {
        view()
            .absolute()
            .inset_0()
            .style_when(move || current.get() != tab, |s| s.hidden())
            .child(tab_content(tab))
    }))
}

/// Presses a tab: the current one pops to its root.
fn choose(tab: Tab) {
    let current = nav::tab();
    if current.get_untracked() == tab {
        nav::pop_to_root();
    }
    current.set(tab);
}

/// The phone's section bar, in the skin's shape: Apple's floating Liquid
/// Glass capsule, Material's navigation bar, Fluent's selector bar,
/// Adwaita's view switcher. Shape and colour both mark the selection.
fn tab_bar() -> View {
    // iOS: the system's own tab bar (UITabBar: Liquid Glass on iOS 26, with
    // the system's morphing selection, haptics and accessibility), not a
    // drawing of one.
    if os() == Os::Ios {
        return native_tab_bar();
    }
    match spec().nav {
        NavChrome::GlassCapsule => glass_tab_bar(),
        NavChrome::NavigationBar => material_bar(),
        NavChrome::SelectorBar => fluent_bar(),
        NavChrome::ViewSwitcher => adwaita_bar(),
    }
}

/// The tab's SF Symbol (iOS's own glyphs in the system tab bar).
fn sf_symbol(tab: Tab) -> &'static str {
    match tab {
        Tab::Chats => "bubble.left.and.bubble.right",
        Tab::Calls => "phone",
        Tab::Communities => "person.3",
        Tab::You => "person.crop.circle",
    }
}

/// iOS's native tab bar, floating over the content at the bottom. The
/// Chats tab carries the unread count as the system's badge (`badgeValue`,
/// which VoiceOver reads with the title).
fn native_tab_bar() -> View {
    use nsh_core::mobile::{TabBarItem, tab_bar};
    let s = store();
    let current = nav::tab();
    let items = move || {
        let unread = s.total_unread();
        Tab::ALL
            .iter()
            .map(|t| {
                let item = TabBarItem::new(t.label()).icon(sf_symbol(*t));
                match (*t, unread) {
                    (Tab::Chats, n) if n > 999 => item.badge("999+"),
                    (Tab::Chats, n) if n > 0 => item.badge(n.to_string()),
                    _ => item,
                }
            })
            .collect::<Vec<TabBarItem>>()
    };
    view().absolute().left_0().right_0().bottom_0().z_index(2).child(
        tab_bar()
            .items(items)
            .selected_index(move || Tab::ALL.iter().position(|t| *t == current.get()).unwrap_or(0) as u32)
            .on_change(move |i: &u32| {
                if let Some(tab) = Tab::ALL.get(*i as usize) {
                    choose(*tab);
                }
            }),
    )
}

/// One tab button with its accessibility and press; the look is the
/// caller's.
fn tab_button(tab: Tab) -> nsh_base::ButtonElement {
    let current = nav::tab();
    button()
        .flex_1()
        .selected(move || current.get() == tab)
        .accessibility_label(tab.label())
        .on_press(move || choose(tab))
        .cursor_pointer()
        .items_center()
        .justify_center()
        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(-2.0)).outline_color(move || c::ring()))
}

/// The tab's label.
fn tab_label(tab: Tab, size: f32, selected: impl Fn() -> bool + Copy + 'static, on: fn() -> AdaptiveColor, off: fn() -> AdaptiveColor) -> Text {
    text(tab.label())
        .number_of_lines(1)
        .text_size(px(size))
        .font_weight(FontWeight::MEDIUM)
        .style_when(selected, |st| st.font_weight(FontWeight::SEMIBOLD))
        .text_color(move || if selected() { on() } else { off() })
}

/// Apple (iOS 26): a capsule of Liquid Glass floating over the content,
/// inset from the edges; the chosen tab sits in a lighter pill, its glyph
/// and label in the tint.
fn glass_tab_bar() -> View {
    let current = nav::tab();
    view()
        .absolute()
        .left_0()
        .right_0()
        .bottom_0()
        .px(px(20.0))
        .pb_safe_area_plus(px(8.0))
        .z_index(2)
        .child(
            view()
                .flex_row()
                .h(px(62.0))
                .p(px(4.0))
                .rounded_full()
                .glass_effect(nsh_core::GlassEffect::Regular)
                .glass_tint_color(Some(c::primary().opacity(0.06)))
                .backdrop_blur(px(24.0))
                .bg(move || c::card().opacity(0.62))
                .border(hairline())
                .border_color(move || c::foreground().opacity(0.08))
                .shadow_lg()
                .shadow_color(c::foreground().opacity(0.12))
                .role(AccessibilityRole::Tablist)
                .children(Tab::ALL.into_iter().map(move |tab| {
                    let selected = move || current.get() == tab;
                    tab_button(tab)
                        .h_full()
                        .rounded_full()
                        .gap(px(1.0))
                        .bg(move || if selected() { c::foreground().opacity(0.07) } else { AdaptiveColor::TRANSPARENT })
                        .transition_colors()
                        .duration(motion::BASE)
                        .active(|st| st.opacity(0.6))
                        .child(
                            view()
                                .w(px(32.0))
                                .h(px(26.0))
                                .items_center()
                                .justify_center()
                                .text_color(move || if selected() { c::primary() } else { c::foreground() })
                                .child(icon(glyph(tab), 23.0))
                                .child((tab == Tab::Chats).then(|| tab_badge((32.0, 26.0), 23.0, c::card))),
                        )
                        .child(tab_label(tab, 10.0, selected, c::primary, c::foreground))
                })),
        )
}

/// Material 3: an 80dp navigation bar on the surface container; the
/// chosen tab's glyph sits in a 64×32 pill on the secondary container.
fn material_bar() -> View {
    let current = nav::tab();
    view()
        .flex_row()
        .bg(move || c::sidebar())
        .pb_safe_area()
        .role(AccessibilityRole::Tablist)
        .children(Tab::ALL.into_iter().map(move |tab| {
            let selected = move || current.get() == tab;
            tab_button(tab)
                .h(px(80.0))
                .pt(px(12.0))
                .pb(px(16.0))
                .gap(px(4.0))
                .justify_start()
                .child(
                    view()
                        .w(px(64.0))
                        .h(px(32.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || if selected() { c::sidebar_accent() } else { AdaptiveColor::TRANSPARENT })
                        .transition_colors()
                        .duration(motion::BASE)
                        // The state layer (Android adds its ripple on views).
                        .active(|st| st.bg(move || c::foreground().opacity(0.12)))
                        .text_color(move || if selected() { c::on_accent() } else { c::muted_fg() })
                        .child(icon(glyph(tab), 24.0))
                        .child((tab == Tab::Chats).then(|| tab_badge((64.0, 32.0), 24.0, c::sidebar))),
                )
                .child(tab_label(tab, 12.0, selected, c::foreground, c::muted_fg))
        }))
}

/// Fluent 2: a bar on the layer, a 1px stroke over it; the chosen item
/// carries the 16×3 accent pill under its label.
fn fluent_bar() -> View {
    let current = nav::tab();
    view()
        .flex_row()
        .bg(move || c::card())
        .border_t_1()
        .border_color(move || c::border())
        .pb_safe_area()
        .px_1()
        .role(AccessibilityRole::Tablist)
        .children(Tab::ALL.into_iter().map(move |tab| {
            let selected = move || current.get() == tab;
            tab_button(tab)
                .h(px(60.0))
                .my_1()
                .gap(px(2.0))
                .rounded(px(4.0))
                .hover(|st| st.bg(move || c::foreground().opacity(0.04)))
                .active(|st| st.bg(move || c::foreground().opacity(0.02)))
                .child(
                    view()
                        .w(px(28.0))
                        .h(px(24.0))
                        .items_center()
                        .justify_center()
                        .text_color(move || if selected() { c::primary() } else { c::muted_fg() })
                        .child(icon(glyph(tab), 20.0))
                        .child((tab == Tab::Chats).then(|| tab_badge((28.0, 24.0), 20.0, c::card))),
                )
                .child(tab_label(tab, 12.0, selected, c::foreground, c::muted_fg))
                .child(
                    view()
                        .w(px(16.0))
                        .h(px(3.0))
                        .rounded_full()
                        .bg(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT }),
                )
        }))
}

/// Adwaita: a flat view-switcher bar under a 1px shade; the chosen
/// switch in a 6pt rounded fill, glyph and label in the accent.
fn adwaita_bar() -> View {
    let current = nav::tab();
    view()
        .flex_row()
        .gap_1()
        .bg(move || c::card())
        .border_t(hairline())
        .border_color(move || c::border())
        .pb_safe_area()
        .p(px(6.0))
        .role(AccessibilityRole::Tablist)
        .children(Tab::ALL.into_iter().map(move |tab| {
            let selected = move || current.get() == tab;
            tab_button(tab)
                .h(px(50.0))
                .gap(px(2.0))
                .rounded(px(6.0))
                .bg(move || if selected() { c::foreground().opacity(0.08) } else { AdaptiveColor::TRANSPARENT })
                .hover(|st| st.bg(move || c::foreground().opacity(0.05)))
                .active(|st| st.bg(move || c::foreground().opacity(0.12)))
                .child(
                    view()
                        .w(px(26.0))
                        .h(px(20.0))
                        .items_center()
                        .justify_center()
                        .text_color(move || if selected() { c::primary() } else { c::foreground() })
                        .child(icon(glyph(tab), 18.0))
                        .child((tab == Tab::Chats).then(|| tab_badge((26.0, 20.0), 18.0, c::card))),
                )
                .child(tab_label(tab, 12.0, selected, c::primary, c::foreground))
        }))
}

/// Phones and narrow windows. Built again when the skin changes (debug).
pub fn phone() -> AnyElement {
    dynamic(move || {
        let _ = skin::tracked_skin();
        untracked(phone_layout)
    })
    .into_element()
}

fn phone_layout() -> AnyElement {
    nav_stack()
        .flex_1()
        .child(
            nav_page()
                .key("root")
                .header_visible(false)
                .child(
                    view()
                        .flex_1()
                        .bg(move || c::background())
                        .pt_safe_area()
                        .child(tab_panels())
                        .child(tab_bar()),
                ),
        )
        .child(pushed())
        .into_element()
}

/// The wide window's section navigation, in the skin's shape.
fn sidebar() -> View {
    match spec().sidebar {
        Sidebar::Rail => rail(),
        _ => side_list(),
    }
}

/// Material 3: the navigation rail, icon in a pill over its label.
fn rail() -> View {
    let current = nav::tab();
    let w = spec().sidebar_w;
    // The logo's centre sits on the list pane header's centre line, so
    // the rail and the panes share one top band.
    view()
        .w(px(w))
        .bg(move || c::sidebar())
        .items_center()
        .pt_3()
        .pb_4()
        .gap_3()
        .role(AccessibilityRole::Tablist)
        .child(
            view()
                .size(px(40.0))
                .mb_4()
                .rounded(px(12.0))
                .bg(move || c::primary())
                .items_center()
                .justify_center()
                .text_color(move || c::on_primary())
                .child(icon(Icon::Feather, 22.0)),
        )
        .children(Tab::ALL.into_iter().map(move |tab| {
            let selected = move || current.get() == tab;
            button()
                .selected(selected)
                .accessibility_label(tab.label())
                .on_press(move || {
                    nav::pop_to_root();
                    current.set(tab);
                })
                .w(px(w - 8.0))
                .items_center()
                .gap_1()
                .cursor_pointer()
                .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
                .child(
                    view()
                        .w(px(56.0))
                        .h(px(32.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || if selected() { c::sidebar_accent() } else { AdaptiveColor::TRANSPARENT })
                        .transition_colors()
                        .duration(motion::BASE)
                        .hover(|st| st.bg(move || c::foreground().opacity(0.08)))
                        .active(|st| st.bg(move || c::foreground().opacity(0.12)))
                        .text_color(move || if selected() { c::on_accent() } else { c::muted_fg() })
                        .child(icon(glyph(tab), 24.0))
                        .child((tab == Tab::Chats).then(|| tab_badge((56.0, 32.0), 24.0, c::sidebar))),
                )
                .child(
                    text(tab.label())
                        .number_of_lines(1)
                        .text_size(px(12.0))
                        .line_height(px(16.0))
                        .font_weight(FontWeight::MEDIUM)
                        .style_when(selected, |st| st.font_weight(FontWeight::BOLD))
                        .text_color(move || if selected() { c::foreground() } else { c::muted_fg() }),
                )
        }))
        .child(view().flex_1())
        .child(profile_button(c::sidebar))
}

/// The user's avatar, which opens You.
fn profile_button(surface: fn() -> AdaptiveColor) -> nsh_base::ButtonElement {
    let current = nav::tab();
    let me = store().me.get_untracked();
    let reduced = motion::reduced();
    button()
        .accessibility_label("Your profile")
        .on_press(move || {
            nav::pop_to_root();
            current.set(Tab::You);
        })
        .rounded_full()
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .hover(|st| st.opacity(0.9))
        .active(move |st| if reduced { st.opacity(0.8) } else { st.scale(motion::ICON_PRESS_SCALE) })
        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(avatar_presence_on(me.name, me.seed, 36.0, || true, surface))
}

/// A sidebar of rows (Apple's source list on the sidebar material,
/// Fluent's NavigationView pane, Adwaita's flat sidebar): glyph and label
/// side by side, the unread count at the end, the chosen row filled.
/// Fluent adds its 3×16 accent pill at the row's leading edge.
fn side_list() -> View {
    let current = nav::tab();
    let s = store();
    let sp = spec();
    let kind = sp.sidebar;
    let mac_material = kind == Sidebar::SourceList && os() == Os::MacOs;
    let (row_h, glyph_size, label_size, corner) = match kind {
        Sidebar::SourceList => (30.0, 17.0, 13.0, 8.0),
        Sidebar::NavigationView => (36.0, 16.0, 14.0, 4.0),
        _ => (38.0, 16.0, 14.0, 6.0),
    };
    let me = s.me.get_untracked();
    let me_name = me.name.clone();
    view()
        .w(px(sp.sidebar_w))
        // macOS: the window's sidebar material (vibrancy) shows through;
        // elsewhere the sidebar colour.
        .bg(move || if mac_material { c::sidebar().opacity(0.55) } else { c::sidebar() })
        .when(mac_material, |v| {
            let mut b = MacOsBackdrop::default();
            b.material = MacOsBackdropMaterial::Sidebar;
            b.blending = MacOsBackdropBlending::BehindWindow;
            v.macos_backdrop(Some(b))
        })
        .when(kind == Sidebar::Flat, |v| v.border_r(hairline()).border_color(move || c::border()))
        .when(kind == Sidebar::SourceList, |v| v.border_r(hairline()).border_color(move || c::border()))
        .role(AccessibilityRole::Tablist)
        // The brand: the feather and the name, where each platform puts the
        // app's title (Adwaita: centred in the sidebar's header bar).
        .child(
            view()
                .h(px(if kind == Sidebar::Flat { sp.header_h } else { 52.0 }))
                .flex_row()
                .items_center()
                .gap_2()
                .px(px(if kind == Sidebar::NavigationView { 14.0 } else { 14.0 }))
                .when(kind == Sidebar::Flat, |v| v.justify_center().border_b(hairline()).border_color(move || c::border()))
                .child(
                    view()
                        .size(px(24.0))
                        .rounded(px(if kind == Sidebar::NavigationView { 4.0 } else { 7.0 }))
                        .bg(move || c::primary())
                        .items_center()
                        .justify_center()
                        .text_color(move || c::on_primary())
                        .child(icon(Icon::Feather, 15.0)),
                )
                .child(
                    text("Songbird")
                        .text_size(px(match kind {
                            Sidebar::NavigationView => 12.0,
                            Sidebar::Flat => 15.0,
                            _ => 13.0,
                        }))
                        .font_weight(if kind == Sidebar::NavigationView { FontWeight::NORMAL } else { FontWeight::BOLD })
                        .text_color(move || c::foreground()),
                ),
        )
        .child(
            view().px(px(if kind == Sidebar::NavigationView { 4.0 } else { 8.0 })).pt_2().gap(px(2.0)).children(Tab::ALL.into_iter().map(
                move |tab| {
                    let selected = move || current.get() == tab;
                    button()
                        .selected(selected)
                        .accessibility_label(tab.label())
                        .on_press(move || {
                            nav::pop_to_root();
                            current.set(tab);
                        })
                        .h(px(row_h))
                        .flex_row()
                        .items_center()
                        .gap(px(10.0))
                        .px(px(if kind == Sidebar::NavigationView { 14.0 } else { 8.0 }))
                        .rounded(px(corner))
                        .cursor_pointer()
                        .bg(move || match (selected(), kind) {
                            (false, _) => AdaptiveColor::TRANSPARENT,
                            (true, Sidebar::NavigationView) => c::foreground().opacity(0.06),
                            (true, Sidebar::SourceList) => c::foreground().opacity(0.09),
                            (true, _) => c::sidebar_accent(),
                        })
                        .transition_colors()
                        .duration(motion::INSTANT)
                        .hover(|st| st.bg(move || c::foreground().opacity(0.05)))
                        .active(|st| st.bg(move || c::foreground().opacity(0.03)))
                        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(-2.0)).outline_color(move || c::ring()))
                        .child((kind == Sidebar::NavigationView).then(|| {
                            view()
                                .absolute()
                                .left(px(0.0))
                                .top(px((row_h - 16.0) / 2.0))
                                .w(px(3.0))
                                .h(px(16.0))
                                .rounded_full()
                                .bg(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
                        }))
                        .child(
                            icon(glyph(tab), glyph_size).text_color(move || match kind {
                                // macOS tints sidebar glyphs; Fluent and
                                // Adwaita draw them in the text colour.
                                Sidebar::SourceList => c::primary(),
                                _ if selected() => c::primary(),
                                _ => c::foreground(),
                            }),
                        )
                        .child(
                            text(tab.label())
                                .flex_1()
                                .number_of_lines(1)
                                .text_size(px(label_size))
                                .font_weight(FontWeight::NORMAL)
                                .style_when(move || selected() && kind != Sidebar::SourceList, |st| st.font_weight(FontWeight::SEMIBOLD))
                                .text_color(move || c::foreground()),
                        )
                        .child((tab == Tab::Chats).then(|| {
                            let count = move || s.total_unread();
                            match kind {
                                // macOS: the count as plain secondary text.
                                Sidebar::SourceList => text(move || count().to_string())
                                    .text_size(px(12.0))
                                    .tabular_nums()
                                    .text_color(move || c::muted_fg())
                                    .style_when(move || count() == 0, |st| st.hidden())
                                    .into_element(),
                                // Fluent's InfoBadge, Adwaita's pill.
                                _ => view()
                                    .style_when(move || count() == 0, |st| st.hidden())
                                    .child(unread_badge(count, || false))
                                    .into_element(),
                            }
                        }))
                },
            )),
        )
        .child(view().flex_1())
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .p_3()
                .child(profile_button(c::sidebar))
                .child(
                    text(me_name)
                        .flex_1()
                        .number_of_lines(1)
                        .text_size(px(label_size))
                        .text_color(move || c::foreground()),
                ),
        )
}

/// The detail pane when no chat is open.
fn welcome_pane() -> AnyElement {
    view()
        .flex_1()
        .bg(move || c::chat_bg())
        .child(empty_state(
            Icon::Lock,
            "Songbird for desktop",
            "Send and receive messages here, even when your phone is off. Your messages are end-to-end encrypted.",
            None,
        ))
        .into_element()
}

/// The detail pane of a section other than Chats, before something in its
/// list is chosen: what to do there, with the section's own mark.
fn section_pane(tab: Tab) -> AnyElement {
    let (glyph, title, message) = match tab {
        Tab::Calls => (Icon::Calls, "Calls", "Choose a call to see its details, or start one."),
        Tab::Communities => (Icon::Communities, "Communities", "Choose a community or channel."),
        Tab::You | Tab::Chats => (Icon::Settings, "Settings", "Choose a setting."),
    };
    view()
        .flex_1()
        .bg(move || c::chat_bg())
        .child(empty_state(glyph, title, message, None))
        .into_element()
}

/// The detail pane's root: the open chat (or the welcome) on Chats, the
/// section's own empty state on the others. The chat stays mounted while
/// another section shows, so going back to Chats returns to it as it was
/// (scroll, draft).
fn detail_root() -> View {
    let open = nav::open_chat();
    let current = nav::tab();
    view()
        .flex_1()
        .child(
            view()
                .absolute()
                .inset_0()
                .style_when(move || current.get() != Tab::Chats, |st| st.hidden())
                .child(dynamic(move || {
                    let chat = open.get().0;
                    untracked(|| match chat {
                        Some(id) => features::chat::conversation(id),
                        None => welcome_pane(),
                    })
                })),
        )
        .children([Tab::Calls, Tab::Communities, Tab::You].into_iter().map(move |tab| {
            view()
                .absolute()
                .inset_0()
                .style_when(move || current.get() != tab, |st| st.hidden())
                .child(section_pane(tab))
        }))
}

/// Wide windows: sidebar, list pane, detail pane. Built again when the
/// skin changes (debug).
pub fn desktop() -> AnyElement {
    dynamic(move || {
        let _ = skin::tracked_skin();
        untracked(desktop_layout)
    })
    .into_element()
}

fn desktop_layout() -> AnyElement {
    let open = nav::open_chat();
    let current = nav::tab();
    // A chat opened from another section (a call's "Message", contact
    // info) shows on Chats: the detail pane belongs to the selected
    // section, so the section follows the chat. Only a change counts, not
    // the chat already open when this layout mounts.
    let seen = stored(open.get_untracked());
    effect(move || {
        let now = open.get();
        if seen.replace(now) != now && now.0.is_some() && current.get_untracked() != Tab::Chats {
            current.set(Tab::Chats);
        }
    });
    let sp = spec();
    // Fluent's NavigationView: the content is a layer on the window, its
    // top-leading corner rounded (8) and outlined by the card stroke.
    let layer = sp.sidebar == Sidebar::NavigationView;
    let panes = view()
        .flex_1()
        .flex_row()
        .overflow_hidden()
        .when(layer, |v| {
            v.rounded_tl(px(8.0)).border_l_1().border_t_1().border_color(move || c::border()).mt(px(8.0))
        })
        .child(
            view()
                .w(px(360.0))
                .border_r(if layer { px(1.0) } else { hairline() })
                .border_color(move || c::border())
                .bg(move || c::background())
                .child(tab_panels()),
        )
        .child(
            nav_stack()
                .flex_1()
                .child(nav_page().key("detail").header_visible(false).child(detail_root()))
                .child(pushed()),
        );
    view()
        .flex_1()
        .flex_row()
        .bg(move || if layer { c::sidebar() } else { c::background() })
        .child(sidebar())
        .child(panes)
        .into_element()
}
