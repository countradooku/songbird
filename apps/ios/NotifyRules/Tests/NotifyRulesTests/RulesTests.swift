import XCTest
@testable import NotifyRules

final class RulesTests: XCTestCase {
    func testAWakeUpShowsTheGenericTextWithSound() {
        let s = decide(Preferences())
        XCTAssertEqual(s, Shown(title: "Songbird", body: "New message", sound: true, suppress: false))
    }

    func testSoundsOffMeansSilent() {
        XCTAssertFalse(decide(Preferences(sound: false)).sound)
    }

    func testMessagesOffSuppresses() {
        let s = decide(Preferences(messages: false))
        XCTAssertTrue(s.suppress)
        XCTAssertFalse(s.sound)
    }

    func testAnOpenedMessageShowsItsSenderAndTextUnlessHidden() {
        let shown = decide(Preferences(), sender: "Ana", text: "hi", chatMuted: false)
        XCTAssertEqual(shown.title, "Ana")
        XCTAssertEqual(shown.body, "hi")
        let hidden = decide(Preferences(hideContent: true), sender: "Ana", text: "hi", chatMuted: false)
        XCTAssertEqual(hidden.title, "Songbird")
        XCTAssertEqual(hidden.body, "New message")
    }

    func testAMutedChatIsSuppressed() {
        XCTAssertTrue(decide(Preferences(), sender: "Ana", text: "hi", chatMuted: true).suppress)
    }

    func testPreferencesReadFromTheAppGroup() {
        let d = UserDefaults(suiteName: "songbird-tests-\(UUID().uuidString)")!
        XCTAssertEqual(Preferences(defaults: d), Preferences())
        d.set(false, forKey: "notify.sound")
        d.set(true, forKey: "notify.hide_content")
        XCTAssertEqual(Preferences(defaults: d), Preferences(messages: true, sound: false, hideContent: true))
        XCTAssertEqual(Preferences(defaults: nil), Preferences())
    }
}
