// Songbird's Notification Service Extension (Prompt 8, D-0099).
//
// Runs on the device for every alert push (`mutable-content: 1`). The push itself says nothing:
// the same title and body for every message. The extension decides what to show from the user's
// own preferences in the App Group (NotifyRules), never from anything the server sent. Once
// app-core (A2) exists it fetches and decrypts the waiting message here and shows its sender and
// text by the same rules.

import UserNotifications
import os

final class NotificationService: UNNotificationServiceExtension {
    private let log = Logger(subsystem: "chat.songbird.app.notify", category: "nse")
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var fallback: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        fallback = content
        let prefs = Preferences(defaults: UserDefaults(suiteName: appGroup))
        let shown = decide(prefs)
        content.title = shown.title
        content.body = shown.body
        content.sound = shown.sound ? .default : nil
        // One notification per kind: a newer wake-up replaces the older one in the list.
        content.threadIdentifier = "songbird"
        content.userInfo["sb.nse"] = 1
        log.notice("songbird-nse processed a wake-up (sound: \(shown.sound, privacy: .public))")
        contentHandler(content)
    }

    // Out of time: show what the push carried, unchanged (it is generic anyway).
    override func serviceExtensionTimeWillExpire() {
        if let handler = contentHandler, let content = fallback {
            handler(content)
        }
    }
}
