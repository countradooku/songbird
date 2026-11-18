//! Navigation: the pushed pages (a global stack every feature can push
//! to, as NSH's gallery does), the selected tab, and the chat open in the
//! desktop layout's detail pane.

use std::rc::Rc;

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
/// tap) is not pushed twice.
pub fn push(key: impl Into<SharedString>, screen: impl Fn() -> Screen + 'static) {
    let route = Route { key: key.into(), screen: Rc::new(screen) };
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

/// The four top-level sections (WhatsApp's layout without Status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Chats,
    Calls,
    Communities,
    You,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Chats, Tab::Calls, Tab::Communities, Tab::You];
    pub fn label(self) -> &'static str {
        match self {
            Tab::Chats => "Chats",
            Tab::Calls => "Calls",
            Tab::Communities => "Communities",
            Tab::You => "You",
        }
    }
}

pub fn tab() -> Signal<Tab> {
    global::<Tab>()
}

/// The chat shown in the desktop layout's detail pane.
#[derive(Default, Clone, Copy, PartialEq)]
pub struct OpenChat(pub Option<ChatId>);

pub fn open_chat() -> Signal<OpenChat> {
    global::<OpenChat>()
}
