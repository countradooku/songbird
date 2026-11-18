//! Where settings rows lead into other features, in one place.

use crate::features;

// Entry points that exist (their owners fill them in).
pub fn linked_devices() {
    features::devices::linked_devices();
}
pub fn backups() {
    features::backups::backup_settings();
}
pub fn subscription() {
    features::plans::subscription();
}
pub fn whatsapp() {
    features::whatsapp::whatsapp_settings();
}
pub fn desktop() {
    features::desktop::desktop_settings();
}
pub fn shortcuts() {
    features::desktop::shortcuts_sheet();
}

pub fn storage_and_data() {
    features::media::storage_and_data();
}
pub fn packs() {
    features::media::packs();
}
pub fn account_security() {
    features::devices::account_security();
}
pub fn backup_wizard() {
    features::backups::backup_wizard();
}
pub fn transfer() {
    features::backups::transfer();
}
pub fn invites() {
    features::plans::invites();
}
pub fn help() {
    features::plans::help();
}
pub fn invite_friend() {
    features::plans::invite_friend();
}
pub fn server() {
    features::server::server_connection();
}
