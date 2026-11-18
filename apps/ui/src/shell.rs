//! The two layouts. Phones: a native stack whose root page holds the four
//! destinations (kept mounted, so each keeps its scroll) over the
//! platform's tab bar. Wide windows (`REDESIGN.md`, Floating): on a quiet
//! canvas, a floating list pane (the destination's content over a
//! destination bar), a floating conversation pane with its own stack (the
//! open chat, and what features push), and a floating info pane while a
//! chat's info is open.

use nsh_base::{button, nav_page, nav_stack};
use nsh_core::{
    desktop::{TitleBarOptions, TitleBarStyle, WindowAttributes},
    element::{AnyElement, desktop::current_window, layout_rtl},
    prelude::*,
};

use crate::{
    features,
    nav::{self, Route, Tab},
    store::store,
    ui::{
        floating::{self, GAP, INFO_W, LIST_W, MARGIN},
        skin::{self, FULL, NavChrome},
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
        Tab::Spaces => Icon::Spaces,
        Tab::You => Icon::You,
    }
}

/// One tab's content, made once per layout.
fn tab_content(tab: Tab) -> AnyElement {
    match tab {
        Tab::Chats => features::chats::chats_tab(),
        Tab::Calls => features::calls::calls_tab(),
        Tab::Spaces => features::groups::spaces_tab(),
        Tab::You => features::settings::you_tab(),
    }
}

/// The four destinations stacked, only the selected one shown. Phones
/// switch at once, as their tab bars do. Wide windows fade the chosen one
/// in (`FAST`, ease-out: sibling sections cross-fade rather than slide;
/// an opacity fade stays with reduced motion), while the one left is
/// hidden at once, so two lists never show through each other.
fn tab_panels(fade: bool) -> View {
    let current = nav::tab();
    view()
        .flex_1()
        .children(Tab::ALL.into_iter().map(move |tab| {
            let shown = move || current.get() == tab;
            let panel = view().absolute().inset_0();
            let panel = if fade {
                panel
                    .opacity(move || if shown() { 1.0_f32 } else { 0.0 })
                    .style_when(move || !shown(), |st| st.invisible())
                    .accessibility_elements_hidden(move || !shown())
                    .transition_opacity()
                    .duration(motion::FAST)
                    .ease_out()
            } else {
                panel.style_when(move || !shown(), |st| st.hidden())
            };
            panel.child(tab_content(tab))
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
        Tab::Spaces => "circle.grid.2x2",
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
    view()
        .absolute()
        .left_0()
        .right_0()
        .bottom_0()
        .z_index(2)
        .child(
            tab_bar()
                .items(items)
                .selected_index(move || {
                    Tab::ALL
                        .iter()
                        .position(|t| *t == current.get())
                        .unwrap_or(0) as u32
                })
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
        .focus_visible(|st| {
            st.outline(px(2.0))
                .outline_offset(px(-2.0))
                .outline_color(move || c::ring())
        })
}

/// The tab's label.
fn tab_label(
    tab: Tab,
    size: f32,
    selected: impl Fn() -> bool + Copy + 'static,
    on: fn() -> AdaptiveColor,
    off: fn() -> AdaptiveColor,
) -> Text {
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
                        .bg(move || {
                            if selected() {
                                c::foreground().opacity(0.07)
                            } else {
                                AdaptiveColor::TRANSPARENT
                            }
                        })
                        .transition_colors()
                        .duration(motion::BASE)
                        .active(|st| st.opacity(0.6))
                        .child(
                            view()
                                .w(px(32.0))
                                .h(px(26.0))
                                .items_center()
                                .justify_center()
                                .text_color(move || {
                                    if selected() {
                                        c::primary()
                                    } else {
                                        c::foreground()
                                    }
                                })
                                .child(icon(glyph(tab), 23.0))
                                .child(
                                    (tab == Tab::Chats)
                                        .then(|| tab_badge((32.0, 26.0), 23.0, c::card)),
                                ),
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
                        .bg(move || {
                            if selected() {
                                c::sidebar_accent()
                            } else {
                                AdaptiveColor::TRANSPARENT
                            }
                        })
                        .transition_colors()
                        .duration(motion::BASE)
                        // The state layer (Android adds its ripple on views).
                        .active(|st| st.bg(move || c::foreground().opacity(0.12)))
                        .text_color(move || {
                            if selected() {
                                c::on_accent()
                            } else {
                                c::muted_fg()
                            }
                        })
                        .child(icon(glyph(tab), 24.0))
                        .child(
                            (tab == Tab::Chats).then(|| tab_badge((64.0, 32.0), 24.0, c::sidebar)),
                        ),
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
                        .text_color(move || {
                            if selected() {
                                c::primary()
                            } else {
                                c::muted_fg()
                            }
                        })
                        .child(icon(glyph(tab), 20.0))
                        .child((tab == Tab::Chats).then(|| tab_badge((28.0, 24.0), 20.0, c::card))),
                )
                .child(tab_label(tab, 12.0, selected, c::foreground, c::muted_fg))
                .child(view().w(px(16.0)).h(px(3.0)).rounded_full().bg(move || {
                    if selected() {
                        c::primary()
                    } else {
                        AdaptiveColor::TRANSPARENT
                    }
                }))
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
                .bg(move || {
                    if selected() {
                        c::foreground().opacity(0.08)
                    } else {
                        AdaptiveColor::TRANSPARENT
                    }
                })
                .hover(|st| st.bg(move || c::foreground().opacity(0.05)))
                .active(|st| st.bg(move || c::foreground().opacity(0.12)))
                .child(
                    view()
                        .w(px(26.0))
                        .h(px(20.0))
                        .items_center()
                        .justify_center()
                        .text_color(move || {
                            if selected() {
                                c::primary()
                            } else {
                                c::foreground()
                            }
                        })
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
            nav_page().key("root").header_visible(false).child(
                view()
                    .flex_1()
                    .bg(move || c::background())
                    .pt_safe_area()
                    .child(tab_panels(false))
                    .child(tab_bar()),
            ),
        )
        .child(pushed())
        .into_element()
}

// ---------------------------------------------------------------- wide

/// Chooses a destination from the destination bar: the conversation
/// pane's pushed pages belong to the destination left, so they go.
fn choose_wide(tab: Tab) {
    nav::pop_to_root();
    nav::tab().set(tab);
}

/// The destination bar's item height and the corner of its selection,
/// per skin: Apple's capsule, Material's 56×32 pill (M3's rail
/// indicator), Fluent's 4pt control corner, Adwaita's 6pt button corner.
fn destination_corner() -> f32 {
    match spec().skin {
        Skin::Apple | Skin::Material => FULL,
        Skin::Fluent => 4.0,
        Skin::Adwaita => 6.0,
    }
}

/// The destination bar's one selection, sliding under the chosen item
/// (`BASE`, ease-in-out; it jumps with reduced motion). Each skin draws
/// it as its own selected navigation item: a neutral capsule (Apple), the
/// secondary-container pill (Material), a subtle fill with the 16×3
/// accent pill under the glyph (Fluent), a 6pt neutral fill (Adwaita).
/// The chosen glyph also turns from muted to full ink, so shape and
/// weight mark the selection, not colour alone.
fn destination_indicator() -> View {
    let current = nav::tab();
    let sk = spec().skin;
    let corner = destination_corner();
    let reduced = motion::reduced();
    // A fraction of its own width (a quarter of the bar): no pixel sums to
    // drift from the items' flex layout. Right to left mirrors the row,
    // so it moves the other way.
    let step = if layout_rtl() { -1.0 } else { 1.0 };
    let at = move || {
        Tab::ALL
            .iter()
            .position(|t| *t == current.get())
            .unwrap_or(0) as f32
    };
    let mark = match sk {
        Skin::Material => view()
            .w(px(56.0))
            .h(px(32.0))
            .rounded_full()
            .bg(move || c::sidebar_accent()),
        Skin::Fluent => view()
            .absolute()
            .inset_0()
            .rounded(px(corner))
            .bg(move || c::foreground().opacity(0.06))
            .items_center()
            .justify_end()
            .child(
                view()
                    .w(px(16.0))
                    .h(px(3.0))
                    .mb(px(2.0))
                    .rounded_full()
                    .bg(move || c::primary()),
            ),
        Skin::Apple | Skin::Adwaita => view()
            .absolute()
            .inset_0()
            .rounded(px(corner))
            .bg(move || c::foreground().opacity(if sk == Skin::Apple { 0.07 } else { 0.08 })),
    };
    view()
        .absolute()
        .top_0()
        .bottom_0()
        .left_0()
        .w(relative(0.25))
        .items_center()
        .justify_center()
        .pointer_events(PointerEvents::None)
        .accessibility_elements_hidden(true)
        .translate_x(move || relative(at() * step))
        .when(!reduced, |v| {
            v.transition_transform()
                .duration(motion::BASE)
                .ease_in_out()
        })
        .child(mark)
}

/// One destination: its glyph (the user's avatar for You) centred in a
/// fixed 28×24 slot, so every glyph's optical centre sits on the item's
/// centre line whatever its drawn width; the Chats unread badge over the
/// slot's corner; the label as a hint on hover and keyboard focus (and to
/// screen readers).
fn destination_item(tab: Tab) -> View {
    let current = nav::tab();
    let s = store();
    let sk = spec().skin;
    let selected = move || current.get() == tab;
    let corner = destination_corner();
    let (slot_w, slot_h, glyph_size) = (28.0, 24.0, 20.0);
    let ink = move || match (sk, selected()) {
        (Skin::Material, true) => c::on_accent(),
        (_, true) => c::foreground(),
        (_, false) => c::muted_fg(),
    };
    let glyph: AnyElement = if tab == Tab::You {
        // The person, not a glyph: their avatar at the glyphs' optical
        // size (a filled disc reads larger than a 2pt outline, so 20 not 24).
        dynamic(move || {
            let me = s.me.get();
            untracked(|| avatar(me.name, me.seed, glyph_size))
        })
        .into_element()
    } else {
        icon(glyph(tab), glyph_size).into_element()
    };
    // The hint sits on a wrapper: buttons take no tooltip of their own.
    let item = button()
        .flex_1()
        .selected(selected)
        .accessibility_label(tab.label())
        .on_press(move || choose_wide(tab))
        .cursor_pointer()
        .items_center()
        .justify_center()
        .rounded(px(corner))
        .transition_colors()
        .duration(motion::INSTANT)
        // The hover wash is a step under the selection's, so hovering the
        // chosen item still reads as chosen.
        .hover(|st| st.bg(move || c::foreground().opacity(0.04)))
        .active(move |st| match sk {
            Skin::Apple => st.opacity(0.6),
            _ => st.bg(move || c::foreground().opacity(0.08)),
        })
        .focus_visible(|st| {
            st.outline(px(2.0))
                .outline_offset(px(2.0))
                .outline_color(move || c::ring())
        })
        .child(
            view()
                .w(px(slot_w))
                .h(px(slot_h))
                .items_center()
                .justify_center()
                .text_color(ink)
                .transition_colors()
                .duration(motion::BASE)
                .child(glyph)
                .child(
                    (tab == Tab::Chats).then(|| tab_badge((slot_w, slot_h), glyph_size, c::pane)),
                ),
        );
    view()
        .flex_1()
        .h_full()
        .tooltip(hint(tab.label()))
        .child(item)
}

/// The destination bar at the bottom of the list pane (it replaces the
/// rail): Chats, Calls, Spaces and You as 20pt glyphs on equal quarters,
/// 8pt in from the pane's edges like the capsules, a hairline over it
/// where the list scrolls beneath (Material: tone and spacing only).
fn destination_bar() -> View {
    let sk = spec().skin;
    view()
        .flex_none()
        .p_2()
        .when(sk != Skin::Material, |v| {
            v.border_t(hairline()).border_color(move || c::border())
        })
        .child(
            view()
                .flex_row()
                .h(px(40.0))
                .role(AccessibilityRole::Tablist)
                .child(destination_indicator())
                .children(Tab::ALL.into_iter().map(destination_item)),
        )
}

/// The conversation pane when no chat is open: the calm welcome.
fn welcome_pane() -> AnyElement {
    view()
        .flex_1()
        .child(empty_state(
            Icon::Lock,
            "Songbird for desktop",
            "Send and receive messages here, even when your phone is off. Your messages are end-to-end encrypted.",
            None,
        ))
        .into_element()
}

/// The conversation pane of a destination other than Chats, before
/// something in its list is chosen: what to do there, with its own mark.
fn section_pane(tab: Tab) -> AnyElement {
    let (glyph, title, message) = match tab {
        Tab::Calls => (
            Icon::Calls,
            "Calls",
            "Choose a call to see its details, or start one.",
        ),
        Tab::Spaces => (Icon::Spaces, "Spaces", "Choose a space or a channel."),
        Tab::You | Tab::Chats => (Icon::Settings, "Settings", "Choose a setting."),
    };
    view()
        .flex_1()
        .child(empty_state(glyph, title, message, None))
        .into_element()
}

/// The conversation pane's root: the open chat (or the welcome) on Chats,
/// the destination's own empty state on the others. The chat stays
/// mounted while another destination shows, so going back to Chats
/// returns to it as it was (scroll, draft). The conversation paints its
/// own per-chat canvas over the pane.
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
        .children(
            [Tab::Calls, Tab::Spaces, Tab::You]
                .into_iter()
                .map(move |tab| {
                    view()
                        .absolute()
                        .inset_0()
                        .style_when(move || current.get() != tab, |st| st.hidden())
                        .child(section_pane(tab))
                }),
        )
}

/// The info pane: a third floating card beside the conversation while a
/// chat's info is open (`nav::show_info`). Its page is built as the info
/// pane's, so its header closes the pane; what it pushes (media, starred)
/// opens in the conversation pane, where there is room for it. Gone, gap
/// and all, while closed.
fn info_slot() -> View {
    let info = nav::info_pane();
    let key = computed(move || info.with(|p| p.0.as_ref().map(|r| r.key.clone())));
    view()
        .w(px(INFO_W))
        .flex_shrink_0()
        .style_when(move || key.with(Option::is_none), |st| st.hidden())
        .child(dynamic(move || {
            let _ = key.get();
            untracked(move || {
                info.with(|p| p.0.clone()).map(|route| {
                    floating::pane()
                        .flex_1()
                        .child(nav_stack().flex_1().child(nav::build_info(&route)))
                })
            })
        }))
}

/// macOS: the window's title bar goes and the traffic lights sit on the
/// canvas, their top-leading corner at the window margin (on the list
/// pane's leading edge). The bar's reported height is then the margin, the
/// lights and the margin again, so the panes start exactly one margin
/// under them (`floating::pane_top`). The system's bar comes back when
/// the wide layout goes (a narrow window's phone layout keeps it).
fn adopt_title_bar() {
    if os() != Os::MacOs {
        return;
    }
    let window = current_window();
    let set = move |style: TitleBarStyle| {
        let mut bar = TitleBarOptions::default();
        bar.style = style;
        if style == TitleBarStyle::Hidden {
            bar.controls_offset = Some(Point {
                x: px(MARGIN),
                y: px(MARGIN),
            });
        }
        let mut attributes = WindowAttributes::default();
        attributes.title_bar = Some(bar);
        window.set(attributes);
    };
    set(TitleBarStyle::Hidden);
    let window = current_window();
    cleanup(move || {
        let mut attributes = WindowAttributes::default();
        attributes.title_bar = Some(TitleBarOptions::default());
        window.set(attributes);
    });
}

/// Wide windows: the canvas and its floating panes. Built again when the
/// skin changes (debug).
pub fn desktop() -> AnyElement {
    adopt_title_bar();
    // Info belongs to the chat and the destination it was opened from.
    cleanup(nav::close_info);
    dynamic(move || {
        let _ = skin::tracked_skin();
        untracked(desktop_layout)
    })
    .into_element()
}

fn desktop_layout() -> AnyElement {
    let open = nav::open_chat();
    let current = nav::tab();
    // A chat opened from another destination (a call's "Message", contact
    // info) shows on Chats: the conversation pane belongs to the selected
    // destination, so the destination follows the chat. Only a change
    // counts, not the chat already open when this layout mounts. Another
    // chat, or another destination, closes the info pane.
    let seen = stored(open.get_untracked());
    effect(move || {
        let now = open.get();
        if seen.replace(now) != now {
            nav::close_info();
            if now.0.is_some() && current.get_untracked() != Tab::Chats {
                current.set(Tab::Chats);
            }
        }
    });
    let seen_tab = stored(current.get_untracked());
    effect(move || {
        let now = current.get();
        if seen_tab.replace(now) != now {
            nav::close_info();
        }
    });
    // Narrowed past room for three panes, the info page moves over the
    // conversation rather than squeezing it.
    effect(move || {
        if !floating::fits_info_pane() {
            untracked(nav::fold_info);
        }
    });
    let mac = os() == Os::MacOs;
    let list = floating::pane()
        .w(px(LIST_W))
        .flex_shrink_0()
        .child(view().flex_1().child(tab_panels(true)))
        .child(destination_bar());
    let conversation = floating::pane().flex_1().min_w_0().child(
        nav_stack()
            .flex_1()
            .child(
                nav_page()
                    .key("detail")
                    .header_visible(false)
                    .child(detail_root()),
            )
            .child(pushed()),
    );
    view()
        .flex_1()
        .bg(move || floating::canvas())
        // The traffic lights' band: the canvas there moves the window.
        .child(mac.then(|| {
            view()
                .absolute()
                .top_0()
                .left_0()
                .right_0()
                .h(move || px(floating::pane_top()))
                .window_drag(true)
                .accessibility_elements_hidden(true)
        }))
        .child(
            view()
                .flex_1()
                .flex_row()
                .gap(px(GAP))
                .pt(move || px(floating::pane_top()))
                .px(px(MARGIN))
                .pb(px(MARGIN))
                .child(list)
                .child(conversation)
                .child(info_slot()),
        )
        .into_element()
}
