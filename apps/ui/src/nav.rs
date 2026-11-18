//! Navigation: the pushed pages (a global stack every feature can push
//! to, as NSH's gallery does), the selected tab, the chat open in the
//! desktop layout's conversation pane, and the page in its info pane.

use std::{cell::Cell, rc::Rc};

use nsh_core::{
    element::{Screen, SharedString, Signal},
    prelude::global,
};

use crate::store::ChatId;

/// What makes a pushed page: made once when pushed.
pub type ScreenFn = Rc<dyn Fn() -> Screen>;

/// A page over the tab root; its key is unique in the stack.
#[derive(Clone)]
pub struct Route {
    pub key: SharedString,
    pub screen: ScreenFn,
}

impl PartialEq for Route {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

#[derive(Default, Clone, PartialEq)]
pub struct Routes(pub Vec<Route>);

pub fn routes() -> Signal<Routes> {
    global::<Routes>()
}

/// Pushes the page `screen` makes. A key already in the stack (a double
/// tap) is not pushed twice. Info pages (keys starting `chat-info:` or
/// `info:`) open in the info pane on wide windows ([`show_info`]).
pub fn push(key: impl Into<SharedString>, screen: impl Fn() -> Screen + 'static) {
    let key: SharedString = key.into();
    if is_info_key(&key) {
        show_info(key, screen);
        return;
    }
    push_route(Route {
        key,
        screen: Rc::new(screen),
    });
}

fn push_route(route: Route) {
    routes().update(|r| {
        if !r.0.iter().any(|x| x.key == route.key) {
            r.0.push(route);
        }
    });
}

pub fn pop() {
    routes().update(|r| {
        r.0.pop();
    });
}

pub fn pop_to_root() {
    routes().update(|r| r.0.clear());
}

pub fn truncate(depth: usize) {
    routes().update(|r| r.0.truncate(depth));
}

pub fn depth() -> usize {
    routes().with_untracked(|r| r.0.len())
}

// ---------------------------------------------------------------- info pane

/// The page in the wide window's info pane (chat or group info), beside
/// the conversation; `None` when it is closed.
#[derive(Default, Clone, PartialEq)]
pub struct InfoPane(pub Option<Route>);

pub fn info_pane() -> Signal<InfoPane> {
    global::<InfoPane>()
}

/// Keys whose pages are a chat's info (`features::chat::chat_info`,
/// `features::groups::group_info`).
fn is_info_key(key: &str) -> bool {
    key.starts_with("chat-info:") || key.starts_with("info:")
}

/// Opens a chat's info: in the info pane on windows wide enough for it
/// beside the conversation (the same page again closes it, so the header
/// that opened it toggles it), pushed elsewhere (over the conversation in
/// its pane, or on the phone's stack).
pub fn show_info(key: impl Into<SharedString>, screen: impl Fn() -> Screen + 'static) {
    let route = Route {
        key: key.into(),
        screen: Rc::new(screen),
    };
    if !crate::ui::floating::fits_info_pane() {
        push_route(route);
        return;
    }
    info_pane().update(|p| {
        p.0 = match p.0.take() {
            Some(open) if open.key == route.key => None,
            _ => Some(route),
        };
    });
}

/// Closes the info pane.
pub fn close_info() {
    if info_pane().with_untracked(|p| p.0.is_some()) {
        info_pane().set(InfoPane(None));
    }
}

/// The window got too narrow for the info pane: its page moves onto the
/// stack, over the conversation, so it stays open where there is room.
pub fn fold_info() {
    let open = info_pane().with_untracked(|p| p.0.clone());
    if let Some(route) = open {
        info_pane().set(InfoPane(None));
        push_route(route);
    }
}

thread_local! {
    static BUILDING_INFO: Cell<bool> = const { Cell::new(false) };
}

/// Builds the info pane's page: while it builds, [`in_info_pane`] holds,
/// so its header closes the pane instead of going back.
pub fn build_info(route: &Route) -> Screen {
    let before = BUILDING_INFO.with(|b| b.replace(true));
    let screen = (route.screen)();
    BUILDING_INFO.with(|b| b.set(before));
    screen
}

/// The page being built is the info pane's.
pub fn in_info_pane() -> bool {
    BUILDING_INFO.with(Cell::get)
}

// ---------------------------------------------------------------- tabs

/// The four destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Chats,
    Calls,
    Spaces,
    You,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Chats, Tab::Calls, Tab::Spaces, Tab::You];
    pub fn label(self) -> &'static str {
        match self {
            Tab::Chats => "Chats",
            Tab::Calls => "Calls",
            Tab::Spaces => "Spaces",
            Tab::You => "You",
        }
    }
}

pub fn tab() -> Signal<Tab> {
    global::<Tab>()
}

/// The chat shown in the desktop layout's conversation pane.
#[derive(Default, Clone, Copy, PartialEq)]
pub struct OpenChat(pub Option<ChatId>);

pub fn open_chat() -> Signal<OpenChat> {
    global::<OpenChat>()
}
