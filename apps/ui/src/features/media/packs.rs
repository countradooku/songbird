//! Stickers and packs: sticker packs, chat scenes, sound stickers and
//! emoticons. Installed packs to reorder and remove, adding one from a
//! link, a preview of the picker, and how GIF search stays private.

use nsh_core::prelude::*;

use crate::features::groups::page_scroll;

use crate::{
    features::groups::glide,
    nav,
    store::{
        ext_groups::{Pack, PackKind, groups_state},
        store,
    },
    ui::*,
};

/// Stickers and packs, pushed (You → Chats → Stickers and packs).
pub fn packs() {
    nav::push("packs", move || {
        let s = store();
        let kind = signal(PackKind::Stickers);
        let link = signal(String::new());
        let error = signal(None::<&'static str>);
        let cleared = signal(0_u32);
        let state = groups_state();
        let installing = move || state.with(|g| g.installing.as_ref().map(|i| i.progress));
        let of_kind = computed(move || {
            let k = kind.get();
            state.with(|g| {
                g.packs
                    .iter()
                    .filter(|p| p.kind == k)
                    .cloned()
                    .collect::<Vec<_>>()
            })
        });
        let add = move || match s.install_pack(link.get_untracked(), kind.get_untracked()) {
            Ok(()) => {
                error.set(None);
                link.set(String::new());
                cleared.update(|n| *n += 1);
            }
            Err(e) => error.set(Some(e)),
        };
        page(
            "Stickers and packs",
            page_scroll(
                view()
                    .pt_1()
                    // Scrolls with a fade at the trailing edge, as the chat
                    // list's filters do, instead of cutting a chip in half.
                    .child(chip_scroller(
                        PackKind::ALL.into_iter().map(move |k| chip(k.label(), move || kind.get() == k, move || kind.set(k)).into_element()),
                        c::background,
                    ))
                    .child(section_title("Preview"))
                    .child(view().px_4().child(picker_preview(of_kind)))
                    .child(section_title(move || format!("Installed {}", kind.get().label().to_lowercase())))
                    .child(dynamic(move || {
                        let list = of_kind.get();
                        untracked(move || installed(s, list))
                    }))
                    // The field's own label ("Pack link") heads this part; a
                    // section title above it said the same thing twice.
                    .child(
                        view()
                            .px_4()
                            .pt_5()
                            .gap_3()
                            .child(
                                view()
                                    .flex_row()
                                    .items_start()
                                    .gap_2()
                                    .child(
                                        view().flex_1().child(labelled_field(
                                            "Pack link",
                                            // A fresh field after each add: a long link
                                            // leaves the text scrolled sideways, and the
                                            // cleared field would show its placeholder cut
                                            // ("ck link"). Remade, it starts at its padding.
                                            dynamic(move || {
                                                let _ = cleared.get();
                                                untracked(move || {
                                                    field("Paste a pack link", link)
                                                        .label("Pack link")
                                                        .keyboard_type(KeyboardType::Url)
                                                        .auto_capitalize(AutoCapitalize::None)
                                                        .on_submit(move |_: &str| add())
                                                })
                                            }),
                                            move || {
                                                error
                                                    .get()
                                                    .map(SharedString::from)
                                                    .unwrap_or_else(|| "Someone shared a pack with you? Paste its link.".into())
                                            },
                                            move || error.get().is_some(),
                                        )),
                                    )
                                    .child(
                                        view().pt(px(22.0)).child(
                                            btn("Add", Variant::Primary, BtnSize::Md, add)
                                                .disabled(move || link.with(|l| l.trim().is_empty()) || installing().is_some()),
                                        ),
                                    ),
                            )
                            .child(when(move || installing().is_some(), move || {
                                let progress = move || installing().unwrap_or(0.0);
                                // Progress in the brand's colour on the card,
                                // the percentage beside it, and Cancel as a
                                // plain text action, not a grey × disc.
                                card()
                                    .flex_row()
                                    .items_center()
                                    .gap_3()
                                    .child(
                                        svg(move || nsh_core::element::ImageSrc::svg_markup(&progress_ring(progress())))
                                            .size(px(36.0))
                                            .text_color(move || c::primary())
                                            .accessibility_elements_hidden(true),
                                    )
                                    .child(
                                        view()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .gap(px(2.0))
                                            .child(
                                                view()
                                                    .flex_row()
                                                    .gap_2()
                                                    .child(text("Adding pack").text_size(px(font::body())).font_weight(FontWeight::MEDIUM))
                                                    .child(
                                                        text(move || format!("{}%", (progress() * 100.0).round() as u32))
                                                            .text_size(px(font::body()))
                                                            .tabular_nums()
                                                            .text_color(move || c::muted_fg()),
                                                    ),
                                            )
                                            .child(muted("Downloading and decrypting. Songbird's servers can't see what's inside.")),
                                    )
                                    .child(btn("Cancel", Variant::Ghost, BtnSize::Sm, move || s.cancel_install()))
                                    .label(move || format!("Adding pack, {}%", (progress() * 100.0).round() as u32))
                            })),
                    )
                    .child(footnote(
                        "Packs are encrypted. Their link carries the key, so only people with the link can open them. Unused packs are deleted after a year.",
                    ))
                    .child(section_title("GIFs"))
                    .child(group([Row::new("GIF search")
                        .icon(Icon::Search)
                        .subtitle("Searches go through Songbird's privacy proxy, so GIF providers never see who you are.")
                        .build()])),
            ),
        )
    });
}

/// The installed packs of one kind, with move up, move down and remove.
fn installed(s: crate::store::Store, list: Vec<Pack>) -> AnyElement {
    if list.is_empty() {
        return view()
            .px_4()
            .child(muted("None installed. Add one from a link below."))
            .into_element();
    }
    let n = list.len();
    // Rules start on the text column (16 + 40 + 12).
    crate::features::groups::card_rows(list.into_iter().enumerate().map(move |(i, p)| {
        let id = p.id;
        let name = p.name.clone();
        let thumb = p.items.first().cloned().unwrap_or_default();
        Row::new(p.name.clone())
            .leading(
                view()
                    .size(px(40.0))
                    .rounded(move || radius::sm())
                    .items_center()
                    .justify_center()
                    .bg(move || c::secondary())
                    .accessibility_elements_hidden(true)
                    .child(text(thumb).text_size(px(22.0))),
            )
            .subtitle(format!("{} · {} items", p.by, p.items.len()))
            .trailing(
                view()
                    .flex_row()
                    .gap_1()
                    .child(
                        reorder_btn(UP, format!("Move {name} up"), move || {
                            glide();
                            s.move_pack(id, true)
                        })
                        .disabled(i == 0),
                    )
                    .child(
                        reorder_btn(DOWN, format!("Move {name} down"), move || {
                            glide();
                            s.move_pack(id, false)
                        })
                        .disabled(i + 1 == n),
                    )
                    .child({
                        let name = name.clone();
                        icon_btn(Icon::Trash, format!("Remove {name}"), move || {
                            let name = name.clone();
                            confirm(
                                format!("Remove “{name}”?"),
                                "It leaves your picker on all your devices. You can add it again from its link.",
                                "Remove",
                                move || {
                                    glide();
                                    s.remove_pack(id);
                                    toast(format!("Removed {name}"));
                                },
                            )
                        })
                    }),
            )
            .build()
    }), 68.0)
    .into_element()
}

/// A progress ring: a faint track and the arc from 12 o'clock, in
/// `currentColor`.
fn progress_ring(p: f32) -> String {
    const R: f32 = 15.0;
    let circumference = 2.0 * std::f32::consts::PI * R;
    let offset = circumference * (1.0 - p.clamp(0.0, 1.0));
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 36 36" fill="none" stroke="currentColor" stroke-linecap="round"><circle cx="18" cy="18" r="{R}" stroke-width="3" opacity="0.2"/><circle cx="18" cy="18" r="{R}" stroke-width="3" stroke-dasharray="{circumference:.2}" stroke-dashoffset="{offset:.2}" transform="rotate(-90 18 18)"/></svg>"#
    )
}

const UP: &str = r#"<path d="m18 15-6-6-6 6"/>"#;
const DOWN: &str = r#"<path d="m6 9 6 6 6-6"/>"#;

/// An icon button with a chevron `icons.rs` lacks (up).
fn reorder_btn(
    shapes: &'static str,
    label: String,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let side = if is_desktop() { 32.0 } else { 44.0 };
    let src = nsh_core::element::ImageSrc::svg_markup(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{shapes}</svg>"#
    ));
    press_surface(Press::Tile, on_press)
        .accessibility_label(label)
        .size(px(side))
        .rounded_full()
        .items_center()
        .justify_center()
        .text_color(move || c::foreground())
        .child(svg(src).size(px(18.0)).accessibility_elements_hidden(true))
}

/// The picker as the composer shows it: the first pack's items in a grid.
fn picker_preview(of_kind: Memo<Vec<Pack>>) -> View {
    card().p_3().gap_2().child(dynamic(move || {
        let packs = of_kind.get();
        untracked(move || {
            let Some(first) = packs.first().cloned() else {
                return muted("Nothing to preview yet.").into_element();
            };
            view()
                .gap_2()
                .child(view().flex_row().gap_2().children(packs.iter().map(|p| {
                    let selected = p.id == first.id;
                    view()
                        .size(px(32.0))
                        .rounded(move || radius::sm())
                        .items_center()
                        .justify_center()
                        .bg(move || {
                            if selected {
                                c::accent()
                            } else {
                                AdaptiveColor::TRANSPARENT
                            }
                        })
                        .label(p.name.clone())
                        .child(
                            text(p.items.first().cloned().unwrap_or_default()).text_size(px(18.0)),
                        )
                })))
                .child(separator())
                .child(
                    view()
                        .flex_row()
                        .flex_wrap()
                        .gap_1()
                        .children(first.items.iter().map(|item| {
                            view()
                                .size(px(52.0))
                                .rounded(move || radius::sm())
                                .items_center()
                                .justify_center()
                                .bg(move || c::secondary())
                                .label(format!("Sticker {item}"))
                                .child(text(item.clone()).text_size(px(28.0)))
                        })),
                )
                .into_element()
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ext_groups::parse_pack_link;

    #[test]
    fn every_kind_has_a_label() {
        for k in PackKind::ALL {
            assert!(!k.label().is_empty());
        }
        assert!(parse_pack_link("nope").is_err());
    }
}
