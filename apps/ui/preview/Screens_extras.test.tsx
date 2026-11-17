// Screenshots of the extras' screens (plans, paywall, invites, help, logs
// preview, WhatsApp, shortcuts, desktop settings, the ui gallery) on macOS
// at desktop and phone sizes, light and dark:
// `cd preview && nsh test Screens_extras.test.tsx --target macos`. Output in ../shots/.
// The preview app is the debug-only ExtrasPreview root, whose invisible
// launcher reaches pages whose entry rows other features own).
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("extras screens", async () => {
  const app = await open(".");
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`../shots/extras-${name}.png`);
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

      await go("open-plans");
      await shot(`plans-${tag}`);
      await go("open-paywall");
      await shot(`paywall-${tag}`);
      await app.press("Get Plus… >> nth=1");
      await shot(`purchase-${tag}`);
      await app.press("Cancel >> nth=0");
      await pause(700);

      await go("open-invites");
      await shot(`invites-${tag}`);
      await go("open-invite-link");
      await shot(`invite-link-${tag}`);

      await go("open-help");
      await shot(`help-${tag}`);
      await app.type("Search help", "backup");
      await shot(`help-search-${tag}`);
      await go("open-contact");
      await shot(`contact-${tag}`);
      await app.press("Preview what is sent");
      await shot(`logs-${tag}`);

      await go("open-wa-optin");
      await shot(`wa-optin-${tag}`);
      await app.press("Link WhatsApp…");
      await app.scroll("Good to know", 1200);
      await shot(`wa-linking-${tag}`);
      await app.press("Cancel");
      await go("open-wa-settings");
      await shot(`wa-settings-${tag}`);

      await go("open-shortcuts");
      await shot(`shortcuts-${tag}`);
      await go("open-desktop");
      await shot(`desktop-settings-${tag}`);
      await go("open-family");
      await shot(`family-${tag}`);
      await go("open-licences");
      await shot(`licences-${tag}`);
    }
  }

  // The gallery, scrolled through, light and dark.
  for (const scheme of ["light", "dark"] as const) {
    await app.setColorScheme(scheme);
    await app.setViewport(1180, 780);
    await go("open-gallery");
    await shot(`gallery-${scheme}-0`);
    for (let i = 1; i <= 9; i++) {
      await app.scroll("Buttons", 640);
      await shot(`gallery-${scheme}-${i}`);
    }
  }
  await app.setViewport(390, 844);
  await go("open-gallery");
  await shot("gallery-phone");
}, 600_000);
