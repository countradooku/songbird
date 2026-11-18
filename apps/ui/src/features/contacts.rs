//! Contacts (Prompt 9, M6): the people the user saved, A–Z, with their
//! notes and Yahoo-style buddy-list groups ("Friends", "Work"). Reached
//! from the You list and from New chat; "Save to contacts" on a shared
//! contact and in contact info adds to it.
//!
//! Every saved contact is an encrypted record (`k/<id>`, PROTOCOL §10.2)
//! that syncs to the user's other devices like a setting; the screens
//! change them only through the store's intents (`save_contact`,
//! `delete_saved_contact`).
//!
//! Motion (DESIGN.md, MOTION_settings.md "Contacts"): rows arrive with the
//! list (no motion of their own), group chips take the chip's selection
//! fade, the edit page pushes natively.

use nsh_core::{element::Position, prelude::*};

use crate::{
    nav,
    store::{SavedContact, store},
    ui::*,
};

/// A stable avatar hue for a saved contact (from its id, never shown).
fn seed_of(id: &str) -> u64 {
    u64::from_str_radix(id.get(..8).unwrap_or("0"), 16).unwrap_or(0)
}

/// What a row says under the name: the groups, then the notes.
pub fn subtitle(c: &SavedContact) -> String {
    let mut parts = Vec::new();
    if !c.groups.is_empty() {
        parts.push(c.groups.join(", "));
    }
    if !c.notes.is_empty() {
        parts.push(c.notes.lines().next().unwrap_or_default().to_string());
    }
    if parts.is_empty() && !c.username.is_empty() {
        parts.push(format!("@{}", c.username));
    }
    parts.join(" · ")
}

/// Saved contacts matching a search (name, username, notes) in a group
/// (`None`: all), A–Z as the book keeps them.
pub fn filtered(all: &[SavedContact], query: &str, group: Option<&str>) -> Vec<SavedContact> {
    let q = query.trim().to_lowercase();
    all.iter()
        .filter(|c| group.is_none_or(|g| c.groups.iter().any(|x| x == g)))
        .filter(|c| {
            q.is_empty()
                || c.name.to_lowercase().contains(&q)
                || c.username.to_lowercase().contains(&q)
                || c.notes.to_lowercase().contains(&q)
        })
        .cloned()
        .collect()
}

/// Opens the Contacts screen.
pub fn open() {
    nav::push("contacts", || {
        page_with(
            "Contacts",
            Some(icon_btn(Icon::Plus, "Add contact", || edit(None)).into_element()),
            body(),
        )
    });
}

fn body() -> impl IntoElement {
    let s = store();
    let book = s.book();
    let query = signal(String::new());
    let group = signal(None::<String>);
    let shown = computed(move || {
        let q = query.get();
        let g = group.get();
        book.with(|b| filtered(&b.0, &q, g.as_deref()))
    });
    let groups = computed(move || s.buddy_groups());
    view()
        .flex_1()
        .child(
            view()
                .px_4()
                .py_2()
                .child(search_field("Search contacts", query)),
        )
        .child(dynamic(move || {
            let gs = groups.get();
            untracked(move || {
                let all = chip("All", move || group.with(Option::is_none), move || {
                    group.set(None)
                })
                .into_element();
                chip_scroller(
                    std::iter::once(all).chain(gs.into_iter().map(|g| {
                        let name = stored(g.clone());
                        let pick = g.clone();
                        chip(
                            g,
                            move || {
                                group.with(|x| name.with(|n| x.as_deref() == Some(n.as_str())))
                            },
                            move || group.set(Some(pick.clone())),
                        )
                        .into_element()
                    })),
                    || if wide() { c::pane() } else { c::background() },
                )
            })
        }))
        .child(
            virtual_list(
                move || shown.with(Vec::len),
                move |at: Position| {
                    let item = computed(move || shown.with(|v| v.get(at.index()).cloned()));
                    // A cell is rebuilt for the contact it shows: saved
                    // contacts carry no live state of their own.
                    dynamic(move || {
                        item.get()
                            .map(|c| {
                                let id = c.id.clone();
                                Row::new(c.name.clone())
                                    .leading(avatar(c.name.clone(), seed_of(&c.id), 40.0))
                                    .subtitle(subtitle(&c))
                                    .chevron()
                                    .on_press(move || edit(Some(id.clone())))
                                    .build()
                            })
                            .unwrap_or_else(|| view().into_element())
                    })
                },
            )
            .keys(move || shown.with(|v| v.iter().map(|c| c.id.clone()).collect::<Vec<_>>()))
            .estimated_item_size(px(if is_desktop() { 52.0 } else { 64.0 }))
            .empty(empty_state(
                Icon::Contact,
                "No contacts here",
                "Save people from a chat, or add someone by their username. Contacts are encrypted and sync to your devices.",
                Some(
                    btn("Add contact", Variant::Primary, BtnSize::Md, || edit(None))
                        .into_element(),
                ),
            ))
            .footer(view().h(px(24.0)))
            .flex_1(),
        )
}

/// Adds (`None`) or edits a saved contact.
pub fn edit(id: Option<String>) {
    let key = format!("contacts:{}", id.as_deref().unwrap_or("new"));
    nav::push(key, move || {
        let title = if id.is_some() {
            "Edit contact"
        } else {
            "New contact"
        };
        page(title, page_scroll(edit_body(id.clone())))
    });
}

fn edit_body(id: Option<String>) -> AnyElement {
    let s = store();
    let existing = id
        .as_deref()
        .and_then(|id| {
            s.book()
                .with_untracked(|b| b.0.iter().find(|c| c.id == id).cloned())
        })
        .unwrap_or_default();
    let name = signal(existing.name.clone());
    let username = signal(existing.username.clone());
    let notes = signal(existing.notes.clone());
    let groups = signal(existing.groups.clone());
    let new_group = signal(String::new());
    let all_groups = signal(s.buddy_groups());
    let invalid = move || name.with(|n| n.trim().is_empty());
    let existing_id = existing.id.clone();
    let save = move || {
        if invalid() {
            toast("Add a name first");
            return;
        }
        s.save_contact(SavedContact {
            id: existing_id.clone(),
            name: name.get_untracked(),
            username: username.get_untracked(),
            notes: notes.get_untracked(),
            groups: groups.get_untracked(),
        });
        nav::pop();
        toast("Contact saved");
    };
    let add_group = move || {
        let g = new_group.with_untracked(|g| g.trim().to_string());
        if g.is_empty() {
            return;
        }
        all_groups.update(|a| {
            if !a.iter().any(|x| x.eq_ignore_ascii_case(&g)) {
                a.push(g.clone());
            }
        });
        groups.update(|gs| {
            if !gs.iter().any(|x| x.eq_ignore_ascii_case(&g)) {
                gs.push(g.clone());
            }
        });
        new_group.set(String::new());
    };
    let delete_id = id.clone();
    view()
        .w_full()
        .max_w(px(640.0))
        .self_center()
        .px_4()
        .pt_4()
        .gap_4()
        .child(labelled_field(
            "Name",
            field("Name", name),
            move || {
                if invalid() {
                    "Needed, so you can find them.".to_string()
                } else {
                    "Only you see this name.".to_string()
                }
            },
            invalid,
        ))
        .child(labelled_field(
            "Username",
            field("Username (optional)", username),
            "Their Songbird username, without the @.",
            || false,
        ))
        .child(labelled_field(
            "Notes",
            field("Notes", notes),
            "Private notes, encrypted like everything here.",
            || false,
        ))
        .child(
            view()
                .gap_2()
                .child(
                    text("Groups")
                        .text_size(px(font::SMALL))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || c::muted_fg())
                        .role(AccessibilityRole::Header),
                )
                .child(dynamic(move || {
                    let all = all_groups.get();
                    untracked(move || {
                        view()
                            .flex_row()
                            .flex_wrap()
                            .gap_2()
                            .label("Groups")
                            .children(all.into_iter().map(move |g| {
                                let name = stored(g.clone());
                                let flip = g.clone();
                                chip(
                                    g,
                                    move || groups.with(|gs| name.with(|n| gs.contains(n))),
                                    move || {
                                        groups.update(|gs| {
                                            if let Some(i) = gs.iter().position(|x| *x == flip) {
                                                gs.remove(i);
                                            } else {
                                                gs.push(flip.clone());
                                            }
                                        })
                                    },
                                )
                            }))
                    })
                }))
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(field("New group", new_group).flex_1().on_submit(move |_: &str| add_group()))
                        .child(btn("Add group", Variant::Secondary, BtnSize::Md, add_group)),
                ),
        )
        .child(btn("Save", Variant::Primary, BtnSize::Lg, save))
        .child(delete_id.map(|id| {
            btn("Delete contact", Variant::Danger, BtnSize::Md, move || {
                let id = id.clone();
                confirm(
                    "Delete this contact?",
                    "They're removed from your contacts on all your devices. Your chats with them stay.",
                    "Delete",
                    move || {
                        s.delete_saved_contact(&id);
                        nav::pop();
                        toast("Contact deleted");
                    },
                )
            })
        }))
        .child(view().h(px(24.0)))
        .into_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(name: &str, groups: &[&str], notes: &str) -> SavedContact {
        SavedContact {
            id: format!("{:032x}", name.len()),
            name: name.into(),
            username: name.to_lowercase(),
            notes: notes.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn search_and_groups_filter_the_book() {
        let all = vec![
            c("Ana", &["Friends"], "climbing"),
            c("Bogdan", &["Work"], ""),
            c("Cora", &["Friends", "Work"], ""),
        ];
        let names = |v: Vec<SavedContact>| v.into_iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(names(filtered(&all, "", None)), ["Ana", "Bogdan", "Cora"]);
        assert_eq!(names(filtered(&all, "", Some("Work"))), ["Bogdan", "Cora"]);
        assert_eq!(names(filtered(&all, "CLIMB", None)), ["Ana"]);
        assert_eq!(
            names(filtered(&all, "bog", Some("Friends"))),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_row_says_groups_then_notes() {
        assert_eq!(
            subtitle(&c("Ana", &["Friends", "Climbing"], "Gym\nmore")),
            "Friends, Climbing · Gym"
        );
        assert_eq!(subtitle(&c("Bo", &[], "")), "@bo");
    }
}
