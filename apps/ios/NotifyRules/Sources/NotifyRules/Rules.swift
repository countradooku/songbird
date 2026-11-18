// What the notification extension shows for a wake-up (Prompt 8, D-0099).
//
// The server's push is always the same: title "Songbird", body "New message", `mutable-content`.
// The extension runs on the device for each one and decides what to show from the user's own
// preferences, which the app keeps in the App Group (`group.chat.songbird.app`): the server never
// learns them. Until app-core (A2) can fetch and decrypt here, the content stays generic; mute per
// chat needs the decrypted message, and suppressing a notification needs Apple's filtering
// entitlement (D-0094 question 2). These rules match `apps/ui/src/features/notify.rs`.

import Foundation

/// The App Group the app and the extension share.
public let appGroup = "group.chat.songbird.app"

/// The user's notification preferences, as the app mirrors them into the App Group.
public struct Preferences: Equatable {
    public var messages: Bool
    public var sound: Bool
    public var hideContent: Bool

    public init(messages: Bool = true, sound: Bool = true, hideContent: Bool = false) {
        self.messages = messages
        self.sound = sound
        self.hideContent = hideContent
    }

    /// Reads them from `defaults` (the App Group's); absent keys keep the defaults.
    public init(defaults: UserDefaults?) {
        self.init()
        guard let d = defaults else { return }
        if d.object(forKey: "notify.messages") != nil { messages = d.bool(forKey: "notify.messages") }
        if d.object(forKey: "notify.sound") != nil { sound = d.bool(forKey: "notify.sound") }
        if d.object(forKey: "notify.hide_content") != nil { hideContent = d.bool(forKey: "notify.hide_content") }
    }
}

/// What to show.
public struct Shown: Equatable {
    public var title: String
    public var body: String
    public var sound: Bool
    /// Show nothing at all (honoured only with the filtering entitlement; otherwise the
    /// extension shows the generic text silently).
    public var suppress: Bool
}

public let genericTitle = "Songbird"
public let genericBody = "New message"

/// The decision for one wake-up whose content the extension could not open (today: always).
public func decide(_ prefs: Preferences) -> Shown {
    if !prefs.messages {
        return Shown(title: genericTitle, body: genericBody, sound: false, suppress: true)
    }
    return Shown(title: genericTitle, body: genericBody, sound: prefs.sound, suppress: false)
}

/// The decision once app-core opened the message: `sender` and `text` are shown unless the user
/// hides content; a muted chat is suppressed.
public func decide(_ prefs: Preferences, sender: String, text: String, chatMuted: Bool) -> Shown {
    if !prefs.messages || chatMuted {
        return Shown(title: genericTitle, body: genericBody, sound: false, suppress: true)
    }
    if prefs.hideContent {
        return Shown(title: genericTitle, body: genericBody, sound: prefs.sound, suppress: false)
    }
    return Shown(title: sender, body: text, sound: prefs.sound, suppress: false)
}
