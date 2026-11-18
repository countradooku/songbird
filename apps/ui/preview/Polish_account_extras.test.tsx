// Polish pass: the extras' screens (plans, paywall, invites, help, contact,
// WhatsApp, shortcuts, desktop settings, licences), desktop light and phone
// dark: `cd preview && nsh test Polish_account_extras.test.tsx --target macos`.
// Output in ../shots/polish/.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ENTRIES = [
  "open-plans", "open-paywall", "open-invites", "open-invite-link", "open-help", "open-contact",
  "open-wa-optin", "open-wa-settings", "open-shortcuts", "open-desktop", "open-licences", "open-family",
];

for (const [w, h, scheme] of [[1180, 780, "light"], [390, 844, "dark"]] as const) {
  const tag = `${w > 700 ? "d" : "p"}-${scheme}`;
  test(`extras ${tag}`, async () => {
    const app = await open(".", { colorScheme: scheme });
    await app.setViewport(w, h);
    await pause(500);
    for (const e of ENTRIES) {
      await app.press(e);
      await pause(650);
      await app.screenshot(`../shots/polish/ext-${tag}-${e.replace("open-", "")}.png`);
      // The paywall is a sheet over the page: close it before the next one.
      if (e === "open-paywall") {
        await app.press("Not now");
        await pause(500);
      }
    }
  }, 240_000);
}
