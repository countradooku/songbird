//! The rest of the You list: chat lists, broadcast lists, starred
//! messages, presence and nudges, parental controls, the proxy.

use nsh_core::prelude::*;

use super::{PRESENCES, presence_name, presence_of, section, section_plain};
use crate::{
    features,
    store::{Body, ChildContact, ContactId, Message, proxy_host, store, when_label},
    ui::*,
};

// ---------------------------------------------------------------- lists

pub fn lists() {
    super::push("Lists", || {
        let s = store();
        let ext = s.ext();
        let draft = signal(String::new());
        let renaming = signal(None::<String>);
        let rename_open = signal(false);
        let rename_to = signal(String::new());
        effect(move || {
            let r = renaming.get();
            untracked(|| {
                if let Some(name) = r {
                    rename_to.set(name);
                    rename_open.set(true);
                }
            });
        });
        let add = move || {
            if s.create_list(draft.get_untracked()) {
                draft.set(String::new());
            } else {
                toast("That list already exists");
            }
        };
        view()
            .child(super::foot("Lists show as filters at the top of Chats. Add a chat to a list from its menu.").pt_4())
            .child(view().pt_3().child(dynamic(move || {
                let names = ext.with(|x| x.lists.clone());
                let len = names.len();
                untracked(move || {
                    group(names.into_iter().enumerate().map(|(i, name)| {
                        let n = s.list_count(&name);
                        let (up, down, edit, del) = (name.clone(), name.clone(), name.clone(), name.clone());
                        Row::new(name.clone())
                            .icon(Icon::Filter)
                            .subtitle(match n {
                                1 => "1 chat".to_string(),
                                n => format!("{n} chats"),
                            })
                            .trailing(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .child(
                                        icon_btn(Icon::ChevronDown, format!("Move {name} up"), move || s.move_list(&up, -1))
                                            .rotate(deg(180.0))
                                            .text_color(move || c::muted_fg())
                                            .disabled(i == 0),
                                    )
                                    .child(
                                        icon_btn(Icon::ChevronDown, format!("Move {name} down"), move || s.move_list(&down, 1))
                                            .text_color(move || c::muted_fg())
                                            .disabled(i + 1 == len),
                                    )
                                    .child(
                                        icon_btn(Icon::Edit, format!("Rename {name}"), move || renaming.set(Some(edit.clone())))
                                            .text_color(move || c::muted_fg()),
                                    )
                                    .child(icon_btn(Icon::Trash, format!("Delete {name}"), move || {
                                        let del = del.clone();
                                        confirm(
                                            format!("Delete the list \"{del}\"?"),
                                            "The chats stay in Chats. Only the list goes.",
                                            "Delete",
                                            move || s.delete_list(&del),
                                        )
                                    })
                                    .text_color(move || c::destructive())),
                            )
                            .build()
                    }))
                })
            })))
            .child(when(
                move || ext.with(|x| x.lists.is_empty()),
                || empty_state(Icon::Filter, "No lists yet", "Make one for Family, Work or anything you like.", None),
            ))
            .child(
                view()
                    .px_4()
                    .pt_4()
                    .flex_row()
                    .gap_2()
                    .child(field("New list name", draft).flex_1().max_length(24).on_submit(move |_: &str| add()))
                    .child(btn("Create", Variant::Primary, BtnSize::Md, add).disabled(move || draft.with(|d| d.trim().is_empty()))),
            )
            .child(app_sheet(
                rename_open,
                "Rename list",
                view()
                    .px_4()
                    .gap_3()
                    .child(field("List name", rename_to).max_length(24))
                    .child(btn("Save", Variant::Primary, BtnSize::Lg, move || {
                        if let Some(from) = renaming.get_untracked() {
                            s.rename_list(&from, rename_to.get_untracked());
                        }
                        rename_open.set(false);
                        renaming.set(None);
                    })),
            ))
            .into_element()
    });
}

// ---------------------------------------------------------------- broadcasts

pub fn broadcasts() {
    super::push("Broadcast lists", || {
        let s = store();
        let ext = s.ext();
        let creating = signal(false);
        let name = signal(String::new());
        let chosen = signal(Vec::<ContactId>::new());
        let people = s.contacts.with_untracked(|cs| cs.iter().filter(|c| !c.blocked && c.id < 16).map(|c| (c.id, c.name.clone())).collect::<Vec<_>>());
        view()
            .child(view().px_4().pt_4().child(banner(
                Tone::Info,
                Icon::Megaphone,
                "One message, sent to each person separately, as if you wrote to them. Replies come to your chat with them. Only people who saved you as a contact get it.",
            )))
            .child(view().pt_4().child(dynamic(move || {
                let list = ext.with(|x| x.broadcasts.clone());
                untracked(move || {
                    group(list.into_iter().map(|b| {
                        let names: Vec<String> = b.members.iter().map(|m| s.contact_name(Some(*m))).collect();
                        let id = b.id;
                        Row::new(b.name.clone())
                            .icon(Icon::Megaphone)
                            .subtitle(names.join(", "))
                            .trailing(
                                icon_btn(Icon::Trash, format!("Delete {}", b.name), move || s.delete_broadcast(id))
                                    .text_color(move || c::destructive()),
                            )
                            .build()
                    }))
                    .style_when(move || ext.with(|x| x.broadcasts.is_empty()), |st| st.hidden())
                })
            })))
            .child(view().px_4().pt_4().child(btn_with_icon(
                "New broadcast list",
                Some(Icon::Plus),
                Variant::Secondary,
                BtnSize::Md,
                move || creating.set(true),
            )))
            .child(app_sheet(
                creating,
                "New broadcast list",
                view()
                    .gap_3()
                    .child(view().px_4().child(field("List name", name).max_length(30)))
                    .child(
                        scroll().max_h(px(300.0)).child(group_plain(people.into_iter().map(move |(id, n)| {
                            toggle_row(n, None, move || chosen.with(|c| c.contains(&id)), move |on| {
                                chosen.update(|c| {
                                    c.retain(|x| *x != id);
                                    if on {
                                        c.push(id);
                                    }
                                })
                            })
                        }))),
                    )
                    .child(
                        view().px_4().child(
                            btn(
                                move || format!("Create with {} people", chosen.with(Vec::len)),
                                Variant::Primary,
                                BtnSize::Lg,
                                move || {
                                    s.create_broadcast(name.get_untracked().trim().to_string(), chosen.get_untracked());
                                    name.set(String::new());
                                    chosen.set(Vec::new());
                                    creating.set(false);
                                },
                            )
                            .disabled(move || name.with(|n| n.trim().is_empty()) || chosen.with(|c| c.len() < 2)),
                        ),
                    ),
            ))
            .into_element()
    });
}

// ---------------------------------------------------------------- starred

/// Starred messages grouped by chat, newest chat first.
pub fn starred_by_chat(all: &[(u64, String, Vec<Message>)]) -> Vec<(u64, String, Vec<Message>)> {
    let mut out: Vec<_> = all
        .iter()
        .map(|(id, title, msgs)| (*id, title.clone(), msgs.iter().filter(|m| m.starred).cloned().collect::<Vec<_>>()))
        .filter(|(_, _, m)| !m.is_empty())
        .collect();
    out.sort_by_key(|(_, _, m)| std::cmp::Reverse(m.iter().map(|x| x.at).max().unwrap_or(i64::MIN)));
    out
}

pub fn starred() {
    super::push("Starred messages", || {
        let s = store();
        let groups = computed(move || {
            let chats = s.chats.with(|cs| cs.iter().map(|c| (c.id, c.title.clone())).collect::<Vec<_>>());
            let all: Vec<_> = chats.into_iter().map(|(id, t)| (id, t, s.messages_of(id))).collect();
            starred_by_chat(&all)
        });
        view()
            .child(when(
                move || groups.with(|g| g.is_empty()),
                || {
                    empty_state(
                        Icon::Star,
                        "No starred messages",
                        "Open a message's menu and choose Star to keep it here.",
                        None,
                    )
                },
            ))
            .child(dynamic(move || {
                let list = groups.get();
                untracked(move || {
                    view().children(list.into_iter().map(|(chat, title, msgs)| {
                        view().child(section_title(title)).child(group_with_inset(msgs.into_iter().map(move |m| {
                            let who = s.contact_name(m.from);
                            let preview = match &m.body {
                                Body::Text(t) => t.clone(),
                                b => b.preview(),
                            };
                            Row::new(preview)
                                .subtitle(format!("{who} · {}", when_label(m.at)))
                                .leading(icon(Icon::Star, 16.0).text_color(move || c::primary()))
                                .chevron()
                                .on_press(move || features::chat::open(chat))
                                .build()
                        // Under the titles: the gutter, the 16pt star and the gap.
                        }), INSET_PLAIN + 16.0 + 12.0))
                    }))
                })
            }))
            .into_element()
    });
}

// ---------------------------------------------------------------- presence

pub fn presence() {
    super::push("Presence and nudges", || {
        let s = store();
        let me = s.me;
        let settings = s.settings;
        let picking = signal(false);
        let off = computed(move || {
            s.contacts.with(|cs| cs.iter().filter(|c| c.nudges_off).map(|c| (c.id, c.name.clone())).collect::<Vec<_>>())
        });
        view()
            .child(super::section_plain(
                "My presence",
                PRESENCES
                    .iter()
                    .map(|(label, line)| {
                        let label: &'static str = label;
                        let line: &'static str = line;
                        radio_row(label, Some(line), move || me.with(|p| presence_name(&p.presence) == label), move || {
                            s.set_presence(presence_of(label))
                        })
                    })
                    .collect(),
            ))
            .child(super::foot("Presence is sent encrypted, only to the contacts your Last seen setting allows. Songbird's servers never show anyone that you're online."))
            .child(super::section_plain(
                "Nudges",
                vec![toggle_row(
                    "Allow nudges",
                    Some("A nudge shakes the chat window to get someone's attention. Off means nobody can nudge you."),
                    move || settings.with(|x| x.nudges),
                    move |v| s.settings_update(|x| x.nudges = v),
                )],
            ))
            .child(when(
                move || settings.with(|x| x.nudges),
                move || {
                    view()
                        .child(section_title("Nudges off for"))
                        .child(dynamic(move || {
                            let list = off.get();
                            untracked(move || {
                                if list.is_empty() {
                                    super::foot("No one. Everyone in your contacts can nudge you.").pt_0().into_element()
                                } else {
                                    group_with_inset(list.into_iter().map(|(id, name)| {
                                        Row::new(name.clone())
                                            .leading(avatar(name, id, 36.0))
                                            .trailing(btn("Allow", Variant::Outline, BtnSize::Sm, move || s.set_nudges_off(id, false)))
                                            .build()
                                    }), INSET_AVATAR)
                                    .into_element()
                                }
                            })
                        }))
                        .child(view().px_4().pt_3().child(btn_with_icon(
                            "Turn off for someone",
                            Some(Icon::BellOff),
                            Variant::Secondary,
                            BtnSize::Md,
                            move || picking.set(true),
                        )))
                },
            ))
            .child(nudge_sheet(picking))
            .into_element()
    });
}

fn nudge_sheet(open: Signal<bool>) -> nsh_base::SheetElement {
    let s = store();
    let people = computed(move || {
        s.contacts.with(|cs| cs.iter().filter(|c| !c.nudges_off && !c.blocked).map(|c| (c.id, c.name.clone())).collect::<Vec<_>>())
    });
    app_sheet(
        open,
        "Turn off nudges from",
        scroll().max_h(px(420.0)).child(view().pb_2().child(dynamic(move || {
            let list = people.get();
            untracked(move || {
                group_with_inset(list.into_iter().map(|(id, name)| {
                    Row::new(name.clone())
                        .leading(avatar(name, id, 36.0))
                        .on_press(move || {
                            s.set_nudges_off(id, true);
                            open.set(false);
                        })
                        .build()
                }), INSET_AVATAR)
            })
        }))),
    )
}

// ---------------------------------------------------------------- parental controls

pub fn parental() {
    super::push("Parental controls", || {
        let s = store();
        let settings = s.settings;
        let ext = s.ext();
        let linked = move || settings.with(|x| x.parental_controls);
        view()
            .child(view().items_center().px_6().pt_6().gap_3().child(hero_icon(Icon::Users)).child(
                body("Help a child use Songbird safely. You choose who can reach them; their messages stay theirs.")
                    .text_center()
                    .max_w(px(420.0)),
            ))
            .child(view().px_4().pt_4().child(banner(
                Tone::Secure,
                Icon::Lock,
                "You'll never see their messages, calls or contacts. Rules only decide who can reach them.",
            )))
            .child(when(move || !linked(), || {
                section(
                    "Get started",
                    vec![
                        Row::new("Supervise a child's account")
                            .icon(Icon::QrCode)
                            .subtitle("Link in person: scan the QR code on their phone.")
                            .chevron()
                            .on_press(link_child)
                            .build(),
                    ],
                )
            }))
            .child(when(linked, move || {
                section(
                    "Supervising",
                    vec![
                        Row::new(ext.with_untracked(|x| x.parental.child_name.clone()))
                            .leading(avatar(ext.with_untracked(|x| x.parental.child_name.clone()), 7, 36.0))
                            .subtitle("Linked in person · rules on")
                            .chevron()
                            .on_press(rules)
                            .build(),
                    ],
                )
            }))
            .child(section(
                "See it from their side",
                vec![Row::new("Preview what your child sees").icon(Icon::Eye).chevron().on_press(child_view).build()],
            ))
            .child(super::foot("A child can't remove these rules alone. They end when you unlink, or on the birthday you both chose when linking (13 to 16, depending on your country)."))
            .into_element()
    });
}

/// Linking in person: the QR on the child's phone, both confirm.
fn link_child() {
    super::push("Link a child's account", || {
        let s = store();
        view()
            .items_center()
            .px_6()
            .pt_6()
            .gap_4()
            .child(qr_code("child-link", 168.0))
            .child(
                view()
                    .gap_3()
                    .max_w(px(420.0))
                    .child(step(1, "On your child's phone, open Songbird → You → Parental controls → I'm a child."))
                    .child(step(2, "Scan the code on their screen with this phone, side by side."))
                    .child(step(3, "Both of you confirm the same four words on each screen.")),
            )
            .child(
                // mock: app-core runs the in-person link and signs the policy with the parent's key (Prompt 9).
                btn("We both confirmed", Variant::Primary, BtnSize::Lg, move || {
                    s.settings_update(|x| x.parental_controls = true);
                    crate::nav::pop();
                    rules();
                }),
            )
            .child(muted("Linking only works in person, so nobody can take over a child's account remotely.").text_center().max_w(px(420.0)))
            .into_element()
    });
}

fn step(n: u32, line: &'static str) -> View {
    view()
        .flex_row()
        .items_start()
        .gap_3()
        .child(
            view()
                .size(px(26.0))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || c::accent())
                .child(text(n.to_string()).text_size(px(font::SMALL)).font_weight(FontWeight::BOLD).text_color(move || c::primary())),
        )
        .child(body(line).flex_1())
}

/// The rules a parent sets.
fn rules() {
    super::push("Rules for Maria", || {
        let s = store();
        let ext = s.ext();
        let p = move |f: fn(&crate::store::ParentalRules) -> bool| move || ext.with(|x| f(&x.parental));
        view()
            .child(view().px_4().pt_4().child(banner(
                Tone::Secure,
                Icon::Lock,
                "You'll never see their messages. These rules are signed by you and shown to them.",
            )))
            .child(section_plain(
                "Who can message them",
                [ChildContact::ApprovedOnly, ChildContact::ContactsAndRequests]
                    .into_iter()
                    .map(|w| {
                        radio_row(w.label(), None, move || ext.with(|x| x.parental.who_can_message == w), move || {
                            s.ext_update(|x| x.parental.who_can_message = w)
                        })
                    })
                    .collect(),
            ))
            .child(section_plain(
                "Groups and calls",
                vec![
                    toggle_row("Group invites need my approval", None, p(|r| r.groups_need_approval), move |v| {
                        s.ext_update(|x| x.parental.groups_need_approval = v)
                    }),
                    toggle_row("Block calls from people not in contacts", None, p(|r| r.block_unknown_calls), move |v| {
                        s.ext_update(|x| x.parental.block_unknown_calls = v)
                    }),
                    toggle_row(
                        "Others can find them by username",
                        Some("Off: only people they add, or you approve, can start a chat."),
                        p(|r| r.discoverable),
                        move |v| s.ext_update(|x| x.parental.discoverable = v),
                    ),
                    toggle_row("Allow nudges", None, p(|r| r.nudges), move |v| s.ext_update(|x| x.parental.nudges = v)),
                ],
            ))
            .child(section_title("Quiet hours"))
            .child(view().px_4().child(segmented(
                vec![(None, "Off"), (Some("21:00–07:00"), "21:00–07:00"), (Some("22:00–07:00"), "22:00–07:00")],
                move || ext.with(|x| x.parental.quiet_hours),
                move |q| s.ext_update(|x| x.parental.quiet_hours = q),
            )))
            .child(super::foot("No notifications during quiet hours, except calls from you."))
            .child(view().pt_4().child(group(vec![Row::new("Unlink")
                .icon(Icon::LogOut)
                .danger()
                .on_press(move || {
                    confirm("Unlink Maria's account?", "The rules stop at once. Maria is told.", "Unlink", move || {
                        s.settings_update(|x| x.parental_controls = false);
                        crate::nav::pop();
                    })
                })
                .build()])))
            .into_element()
    });
}

/// The child's side (mock): which rules apply, set by whom.
fn child_view() {
    super::push("Rules from Mama", || {
        let s = store();
        let ext = s.ext();
        let rules = move || {
            ext.with(|x| {
                let r = &x.parental;
                let mut out = vec![format!("Who can message you: {}", r.who_can_message.label().to_lowercase())];
                if r.groups_need_approval {
                    out.push("Group invites wait for Mama to approve".into());
                }
                if r.block_unknown_calls {
                    out.push("Calls only from your contacts".into());
                }
                if !r.discoverable {
                    out.push("People can't find you by username".into());
                }
                if let Some(q) = r.quiet_hours {
                    out.push(format!("Quiet hours {q}"));
                }
                out
            })
        };
        view()
            .child(view().px_4().pt_4().child(banner(
                Tone::Secure,
                Icon::ShieldCheck,
                "These rules are set by Mama. They can't read your messages.",
            )))
            .child(section_title("Rules that apply to you"))
            .child(dynamic(move || {
                let list = rules();
                untracked(move || group(list.into_iter().map(|r| Row::new(r).icon(Icon::Check).build())))
            }))
            .child(super::foot("Mama can't see your chats, calls, photos or contacts. The rules end on your 16th birthday, as you both agreed."))
            .into_element()
    });
}

// ---------------------------------------------------------------- proxy

pub fn proxy() {
    super::push("Proxy", || {
        let s = store();
        let settings = s.settings;
        let link = signal(String::new());
        let current = move || settings.with(|x| x.proxy.clone());
        let parsed = move || link.with(|l| proxy_host(l));
        let invalid = move || link.with(|l| !l.trim().is_empty()) && parsed().is_none();
        view()
            .child(
                view().px_4().pt_4().child(
                    card()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        // The standard lavender tile; on or off is said in words.
                        .child(icon_tile(Icon::Globe))
                        .child(
                            view()
                                .flex_1()
                                .min_w(px(0.0))
                                .gap(px(2.0))
                                .child(
                                    text(move || if current().is_some() { "Proxy on" } else { "Proxy off" })
                                        .text_size(px(font::body()))
                                        .font_weight(FontWeight::SEMIBOLD),
                                )
                                .child(muted(move || match current() {
                                    Some(h) => format!("Connected through {h}"),
                                    None => "Connecting to Songbird directly".into(),
                                })),
                        )
                        .child(toggle(
                            "Use proxy",
                            move || current().is_some(),
                            move |on| {
                                if on {
                                    match parsed() {
                                        Some(h) => s.settings_update(|x| x.proxy = Some(h)),
                                        None => toast("Paste a proxy link first"),
                                    }
                                } else {
                                    s.settings_update(|x| x.proxy = None);
                                }
                            },
                        )),
                ),
            )
            .child(
                view().px_4().pt_4().gap_3().child(labelled_field(
                    "Proxy link",
                    field("https://songbird.chat/proxy#…", link)
                        .auto_capitalize(AutoCapitalize::None)
                        .keyboard_type(KeyboardType::Url),
                    move || {
                        if invalid() {
                            "That isn't a proxy link. Ask whoever runs the proxy for its link.".to_string()
                        } else if let Some(h) = parsed() {
                            format!("Proxy at {h}")
                        } else {
                            "Paste a link someone you trust shared with you.".to_string()
                        }
                    },
                    invalid,
                ))
                .child(view().flex_row().child(
                    // mock: app-core reconnects through the proxy (Prompt 1, censorship-resistant proxy).
                    btn("Connect", Variant::Primary, BtnSize::Md, move || {
                        if let Some(h) = parsed() {
                            s.settings_update(|x| x.proxy = Some(h.clone()));
                            link.set(String::new());
                            toast(format!("Connected through {h}"));
                        }
                    })
                    .disabled(move || parsed().is_none()),
                )),
            )
            .child(section_title("What a proxy does"))
            .child(
                view()
                    .px_4()
                    .gap_2()
                    .child(muted("A proxy helps where Songbird is blocked. Your messages stay end\u{2011}to\u{2011}end encrypted through it."))
                    .child(muted("The proxy's operator sees your IP address and when you connect, never your messages or who you talk to."))
                    .child(muted("Songbird's servers see the proxy's address instead of yours.")),
            )
            .into_element()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::Body, ui::Tick};

    fn msg(id: u64, chat: u64, at: i64, starred: bool) -> Message {
        Message {
            id,
            chat,
            from: None,
            body: Body::Text(format!("m{id}")),
            at,
            status: Tick::Read,
            reply_to: None,
            reactions: vec![],
            edited: false,
            starred,
            pinned: false,
            forwarded: false,
            receipts: vec![],
        }
    }

    #[test]
    fn starred_groups_by_chat_newest_first() {
        let all = vec![
            (1, "A".to_string(), vec![msg(1, 1, -100, true), msg(2, 1, -5, false)]),
            (2, "B".to_string(), vec![msg(3, 2, -10, true), msg(4, 2, -50, true)]),
            (3, "C".to_string(), vec![msg(5, 3, -1, false)]),
        ];
        let out = starred_by_chat(&all);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 2);
        assert_eq!(out[0].2.len(), 2);
        assert_eq!(out[1].0, 1);
    }
}
