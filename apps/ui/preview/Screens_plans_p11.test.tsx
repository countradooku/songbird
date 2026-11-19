// Prompt 11, M7: the account's standing (limited, suspended) with its appeal, the Help form's
// "About my account" choice and consent to logs, and the Family page, headless on macOS at
// desktop and phone sizes, light and dark:
// `cd preview && nsh test Screens_plans_p11.test.tsx --target macos`. Output in ../shots/.
import { expect, open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("standing, appeal, contact, family", async () => {
  const app = await open(".");
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`../shots/p11-${name}.png`);
  };
  const go = async (entry: string) => {
    await pause(300);
    await app.press(entry);
  };

  for (const scheme of ["light", "dark"] as const) {
    await app.setColorScheme(scheme);
    for (const [w, h, size] of [
      [1180, 780, "desktop"],
      [390, 844, "phone"],
    ] as const) {
      await app.setViewport(w, h);
      await pause(400);
      const tag = `${size}-${scheme}`;

      // Good standing: no banner.
      await go("standing-good");
      await go("pop-root");
      await pause(300);
      expect(app.texts().some((t: string) => t.includes("New conversations are slowed"))).toBe(false);

      // Limited: a calm banner on Chats, and what it means.
      await go("standing-limited");
      await go("pop-root");
      await app.waitFor("New conversations are slowed for a while. Your chats with contacts aren't affected.");
      await shot(`limited-${tag}`);
      await app.press("What this means");
      await app.waitFor("Account status");
      await shot(`limited-page-${tag}`);

      // Suspended: the page says what still works; the appeal needs a few words.
      await go("standing-suspended");
      await app.waitFor("Tell us why this is a mistake");
      expect(app.texts().some((t: string) => t.includes("You still receive messages"))).toBe(true);
      await app.type("What happened", "I only messaged people I know.");
      await shot(`suspended-${tag}`);
      await app.press("Send appeal");
      await app.waitFor("Appeal sent. A moderator will review it.");
      await go("standing-good");

      // Help: the account is attached only when the user says so; logs only with consent.
      await go("open-contact");
      await app.waitFor("About my account");
      expect(app.texts().some((t: string) => t.includes("Leave it off to write anonymously."))).toBe(true);
      expect(app.texts().some((t: string) => t.includes("They are attached only if you turn this on."))).toBe(true);
      await shot(`contact-${tag}`);

      // Family (the mock plan): the page and its invite sheet.
      await go("open-family");
      await shot(`family-${tag}`);
    }
  }
}, 300_000);
