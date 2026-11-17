//! A7: media, attachments and packs — the media viewer, attachment send
//! progress, storage and data, and stickers and packs.

mod packs;
mod storage;
mod upload;
mod viewer;

pub use packs::packs;
pub use storage::{manage_storage, storage_and_data};
pub use upload::{Upload, ring_markup, simulate_upload, upload_progress};
pub use viewer::{fit, media_ids, save_blocked, step};

use crate::{
    nav,
    store::{ChatId, MsgId},
};

/// Opens the full-screen viewer on `msg`, with the chat's other photos
/// and videos a swipe or an arrow key away.
pub fn open_viewer(chat: ChatId, msg: MsgId) {
    nav::push(format!("viewer:{chat}"), move || viewer::viewer_page(chat, msg));
}
