//! A4 identity and devices: safety numbers, linked devices and account
//! security (username link, two-step PIN, passkeys, accounts, deletion).

mod account;

use std::time::Duration;

use nsh_core::prelude::*;

pub use account::{account_security, account_switcher};

use crate::{
    nav,
    store::{ContactId, Device, DeviceKind, Store, ext_onboarding::safety_groups, store},
    ui::*,
};

/// The most devices linked to one account, besides the phone.
pub const MAX_LINKED: usize = 4;

// ---------------------------------------------------------------- safety number

/// The safety-number screen for a contact, pushed.
pub fn safety_number(contact: ContactId) {
    nav::push(format!("safety:{contact}"), move || {
        page("Safety number", safety_body(contact))
    });
}

fn first_name(name: &str) -> String {
    name.split_whitespace().next().unwrap_or(name).to_string()
}

fn safety_body(contact: ContactId) -> AnyElement {
    let s = store();
    let Some(person) = s.contact(contact) else {
        return empty_state(
            Icon::User,
            "Contact not found",
            "They may have been removed.",
            None,
        )
        .into_element();
    };
    let me = s.me.get_untracked();
    let first = first_name(&person.name);
    let verified = move || s.contact(contact).is_some_and(|c| c.verified);
    let key_changed = move || s.contact(contact).is_some_and(|c| c.key_changed);
    let scanning = signal(false);
    let groups = safety_groups(&person.safety_number);
    let spoken = groups.join(" ");
    let wide_layout = wide();

    let number = view()
        .flex_row()
        .flex_wrap()
        .justify_center()
        .gap_x_4()
        .gap_y_2()
        .max_w(px(320.0))
        .role(AccessibilityRole::Text)
        .label(format!("Safety number: {spoken}"))
        .children(groups.into_iter().map(|g| {
            text(g)
                .w(px(64.0))
                .text_center()
                .font_family(MONO)
                .tabular_nums()
                .text_size(px(font::TITLE))
                .letter_spacing(px(1.0))
                .accessibility_elements_hidden(true)
        }));

    let changed_note = format!(
        "{first}'s safety number changed. This usually means they reinstalled Songbird or got a new phone. Compare the new number to be sure."
    );
    let first2 = first.clone();
    let first3 = first.clone();
    let content = view()
        .w_full()
        .max_w(px(560.0))
        .self_center()
        .px_4()
        .pt_6()
        .gap_5()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_center()
                .gap_3()
                .child(avatar(me.name.clone(), me.seed, 56.0))
                .child(
                    view()
                        .size(px(32.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || c::accent())
                        .text_color(move || c::primary())
                        .accessibility_elements_hidden(true)
                        .child(icon(Icon::Lock, 16.0)),
                )
                .child(avatar(person.name.clone(), person.id, 56.0)),
        )
        .child(
            text(format!("Verify end\u{2011}to\u{2011}end encryption with {}", person.name))
                .text_size(px(font::HEADING))
                .font_weight(FontWeight::SEMIBOLD)
                .text_center()
                .role(AccessibilityRole::Header),
        )
        .child(when(key_changed, move || banner(Tone::Info, Icon::Info, changed_note.clone())))
        .child(
            card()
                .gap_5()
                .items_center()
                .py_5()
                .child(number)
                .child(
                    view()
                        .role(AccessibilityRole::Image)
                        .label(format!("Code for {first2} to scan"))
                        .child(qr_code(&person.safety_number, if wide_layout { 168.0 } else { 152.0 })),
                )
                .child(
                    view()
                        .flex_row()
                        .gap_2()
                        .child(btn_with_icon("Scan code", Some(Icon::Scan), Variant::Secondary, BtnSize::Md, move || {
                            scanning.set(true)
                        }))
                        .child(btn_with_icon("Copy", Some(Icon::Copy), Variant::Ghost, BtnSize::Md, {
                            let number = person.safety_number.clone();
                            move || {
                                set_clipboard(number.clone());
                                toast("Safety number copied");
                            }
                        })),
                ),
        )
        .child(
            group([toggle_row(
                "Mark as verified",
                Some("Turn on after the numbers match. You'll see a shield next to their name."),
                verified,
                move |v| {
                    s.verify(contact, v);
                    if v {
                        toast(format!("{first3} is verified"));
                    }
                },
            )])
            .mx_0(),
        )
        .child(
            view()
                .gap_2()
                .child(muted(format!(
                    "To check that no one is listening in, compare these numbers with {first} in person or on a call, or scan each other's code. If they match, your messages and calls are end\u{2011}to\u{2011}end encrypted with {first} and no one else."
                )))
                .child(view().flex_row().child(
                    // The ghost button's own inset pulled back, so its label
                    // sits on the paragraph's edge.
                    btn("Learn more", Variant::Ghost, BtnSize::Sm, || {
                        // An external page: opens in the browser.
                        let _ = open_url("https://songbird.chat/help/safety-numbers");
                    })
                    .ml(px(-12.0)),
                )),
        );

    view()
        .flex_1()
        .child(page_scroll(content))
        .child(scan_sheet(s, contact, scanning, first))
        .into_element()
}

/// The scanner, mocked: after a moment it reads a matching code.
fn scan_sheet(
    s: Store,
    contact: ContactId,
    open: Signal<bool>,
    first: String,
) -> nsh_base::SheetElement {
    let matched = signal(false);
    let caption = format!("Point your camera at {first}'s code.");
    app_sheet(
        open,
        "Scan code",
        view()
            .px_4()
            .pb_4()
            .gap_4()
            .items_center()
            .child(dynamic(move || {
                let is_open = open.get();
                let caption = caption.clone();
                untracked(move || {
                    if !is_open {
                        matched.set(false);
                        return view().into_element();
                    }
                    // mock: the camera reads their code after a moment (app-core compares fingerprints).
                    set_timeout(Duration::from_millis(2200), move || {
                        if open.try_get() == Some(true) {
                            let _ = matched.try_set(true);
                        }
                    });
                    when(move || matched.get(), move || {
                        view()
                            .items_center()
                            .gap_3()
                            .py_4()
                            .child(hero_icon(Icon::ShieldCheck))
                            .child(
                                text("The numbers match")
                                    .text_size(px(font::TITLE))
                                    .font_weight(FontWeight::SEMIBOLD),
                            )
                            .child(muted("Your chat is end\u{2011}to\u{2011}end encrypted. Mark it as verified?").text_center())
                            .child(
                                view()
                                    .flex_row()
                                    .gap_2()
                                    .child(btn("Not now", Variant::Ghost, BtnSize::Md, move || open.set(false)))
                                    .child(btn("Mark as verified", Variant::Primary, BtnSize::Md, move || {
                                        s.verify(contact, true);
                                        open.set(false);
                                        toast("Verified");
                                    })),
                            )
                    })
                    .otherwise(move || scanner(240.0, caption.clone()))
                    .into_element()
                })
            })),
    )
}

// ---------------------------------------------------------------- linked devices

/// Linked devices, pushed.
pub fn linked_devices() {
    nav::push("linked-devices", || page("Linked devices", devices_body()));
}

fn device_icon(kind: DeviceKind) -> Icon {
    match kind {
        DeviceKind::Phone => Icon::Smartphone,
        DeviceKind::Tablet => Icon::Tablet,
        DeviceKind::Desktop => Icon::Laptop,
    }
}

/// Which listed device is the one the app runs on. The store's flag wins
/// when its kind fits the platform (a computer on desktop, a phone or tablet
/// elsewhere); otherwise the first device of the platform's kind is this one,
/// so a desktop never marks the phone as "This device".
pub fn this_device_id(devices: &[Device]) -> Option<u64> {
    let fits = |d: &Device| (d.kind == DeviceKind::Desktop) == is_desktop();
    devices
        .iter()
        .find(|d| d.this_device && fits(d))
        .or_else(|| devices.iter().find(|d| fits(d)))
        .or_else(|| devices.iter().find(|d| d.this_device))
        .map(|d| d.id)
}

/// The devices with `this_device` following the platform (see
/// [`this_device_id`]).
fn devices_here(devices: Vec<Device>) -> Vec<Device> {
    let this = this_device_id(&devices);
    devices
        .into_iter()
        .map(|mut d| {
            d.this_device = Some(d.id) == this;
            // The seed says "This device" on the phone; elsewhere that is
            // the computer, so the phone is simply active.
            if d.this_device || d.last_active == "This device" {
                d.last_active = "Active now".into();
            }
            d
        })
        .collect()
}

fn devices_body() -> AnyElement {
    let s = store();
    let link_open = signal(false);
    let selected = signal(None::<Device>);
    let detail_open = signal(false);
    let linked = move || s.devices.with(|d| d.len().saturating_sub(1));
    let full = move || linked() >= MAX_LINKED;

    let header = view()
        .items_center()
        .gap_3()
        .px_4()
        .pt_6()
        .pb_2()
        .child(hero_icon(Icon::Laptop))
        .child(
            muted("Use Songbird on your computers and tablets, even when your phone is off.")
                .text_center()
                .max_w(px(360.0)),
        )
        .child(
            btn_with_icon(
                "Link a device",
                Some(Icon::QrCode),
                Variant::Primary,
                BtnSize::Md,
                move || link_open.set(true),
            )
            .disabled(full),
        )
        .child(when(full, || {
            muted("You've linked 4 devices. Log one out to link another.").text_center()
        }));

    let list = dynamic(move || {
        let devices = devices_here(s.devices.get());
        untracked(move || {
            group(devices.into_iter().map(move |d| {
                let leading = icon_tile(device_icon(d.kind));
                let subtitle = if d.this_device {
                    "Active now".to_string()
                } else {
                    d.last_active.clone()
                };
                let row = Row::new(d.name.clone()).leading(leading).subtitle(subtitle);
                let row = if d.this_device {
                    row.trailing(tag("This device"))
                } else {
                    row.chevron()
                };
                row.on_press(move || {
                    selected.set(Some(d.clone()));
                    detail_open.set(true);
                })
                .build()
            }))
            .into_element()
        })
    });

    view()
        .flex_1()
        .child(page_scroll(
            view()
                .w_full()
                .max_w(px(760.0))
                .self_center()
                .child(header)
                .child(section_title("Devices"))
                .child(list)
                .child(crate::features::settings::foot(
                    "You can link up to 4 devices. Messages stay end\u{2011}to\u{2011}end encrypted on every one.",
                )),
        ))
        .child(link_sheet(s, link_open))
        .child(device_sheet(s, detail_open, selected))
        .into_element()
}

/// Linking: steps, the scanner (mocked), then the new device in the list.
fn link_sheet(s: Store, open: Signal<bool>) -> nsh_base::SheetElement {
    app_sheet(
        open,
        "Link a device",
        view().px_4().pb_4().gap_4().child(dynamic(move || {
            let is_open = open.get();
            untracked(move || {
                if !is_open {
                    return view().into_element();
                }
                // mock: the camera reads the other device's code (app-core `link_device`; asks for the PIN when it's on).
                set_timeout(Duration::from_millis(3000), move || {
                    if open.try_get() == Some(true) {
                        let name = s.link_scanned_device();
                        open.set(false);
                        toast(format!("{name} is linked"));
                    }
                });
                let pin_note = when(
                    move || s.settings.with(|x| x.two_step_pin),
                    || muted("Your phone may ask for your two-step PIN.").text_center(),
                );
                if is_desktop() {
                    // Roles: the new device shows a code and the main phone
                    // scans it. A computer has no camera to point, so here
                    // it only explains the steps and waits for the link.
                    return view()
                        .gap_5()
                        .child(
                            view()
                                .gap_3()
                                .child(numbered_step(1, "On the new computer or tablet, open Songbird and choose \"Link to another device\". It shows a code."))
                                .child(numbered_step(2, "On your phone, go to You → Linked devices → Link a device."))
                                .child(numbered_step(3, "Point your phone at the code on the new device.")),
                        )
                        .child(
                            view()
                                .gap_2()
                                .child(busy_bar("Waiting for the new device"))
                                .child(muted("Waiting for the new device…").text_center()),
                        )
                        .child(pin_note)
                        .into_element();
                }
                view()
                    .gap_4()
                    .child(
                        view()
                            .gap_3()
                            .child(numbered_step(1, "Open Songbird on your computer or tablet."))
                            .child(numbered_step(2, "Choose \"I already have an account\", then \"Link to another device\"."))
                            .child(numbered_step(3, "Point this phone at the code it shows.")),
                    )
                    .child(scanner(220.0, "Looking for a code…"))
                    .child(pin_note)
                    .into_element()
            })
        })),
    )
}

/// A device's sheet: rename it, or log it out.
fn device_sheet(
    s: Store,
    open: Signal<bool>,
    selected: Signal<Option<Device>>,
) -> nsh_base::SheetElement {
    let name = signal(String::new());
    app_sheet(
        open,
        "Device",
        view().px_4().pb_4().gap_4().child(dynamic(move || {
            let device = selected.get();
            let is_open = open.get();
            untracked(move || {
                let Some(d) = device.filter(|_| is_open) else { return view().into_element() };
                name.set(d.name.clone());
                let id = d.id;
                let this = d.this_device;
                let original = d.name.clone();
                let save = move || {
                    let n = name.get_untracked().trim().to_string();
                    if !n.is_empty() {
                        s.rename_device(id, n);
                        open.set(false);
                        toast("Device renamed");
                    }
                };
                view()
                    .gap_4()
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_3()
                            .child(icon_tile(device_icon(d.kind)))
                            .child(
                                view()
                                    .flex_1()
                                    .child(text(d.name.clone()).text_size(px(font::body())).font_weight(FontWeight::SEMIBOLD))
                                    .child(muted(if this { "This device".to_string() } else { d.last_active.clone() })),
                            ),
                    )
                    .child(labelled_field(
                        "Name",
                        field("Device name", name).on_submit(move |_: &str| save()).max_length(40),
                        "Only you see this name.",
                        || false,
                    ))
                    .child(
                        btn("Save name", Variant::Primary, BtnSize::Md, save)
                            .disabled(move || name.with(|n| n.trim().is_empty())),
                    )
                    .child(if this {
                        muted("This is the device you're using. To stop using Songbird here, delete the app or your account.")
                            .into_element()
                    } else {
                        btn_with_icon("Log out device", Some(Icon::LogOut), Variant::Danger, BtnSize::Md, move || {
                            let device_name = original.clone();
                            confirm(
                                format!("Log out {device_name}?"),
                                "It stops getting messages, and its chats are deleted from it.",
                                "Log out",
                                move || {
                                    s.remove_device(id);
                                    open.set(false);
                                    toast(format!("{device_name} was logged out"));
                                },
                            )
                        })
                        .into_element()
                    })
                    .into_element()
            })
        })),
    )
}
