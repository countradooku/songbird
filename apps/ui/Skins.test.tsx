// Platform skins (src/ui/skin.rs) on this Mac: the shell, a chat, settings
// with switches and a sheet, desktop and phone width, light and dark.
// `SONGBIRD_ONBOARDED=1 SONGBIRD_SKIN=<skin> nsh test Skins.test.tsx --target macos`
// with `SKIN` below set to the same name (the TS runtime has no env).
// Output: shots/skin-<skin>-<layout>-<scheme>-*.png.
import { open, test } from "nsh/test";

const SKIN = "apple";
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function run(layout: "desktop" | "phone", scheme: "light" | "dark") {
  const app = await open(".", { storage: { onboarded: "1" }, colorScheme: scheme });
  await pause(300);
  await app.setColorScheme(scheme);
  if (layout === "phone") await app.setViewport(390, 844);
  else await app.setViewport(1180, 780);
  await pause(600);
  const tag = `shots/skin-${SKIN}-${layout}-${scheme}`;
  await app.screenshot(`${tag}-chats.png`);
  await app.press("Ana Popescu >> nth=0");
  await pause(600);
  await app.screenshot(`${tag}-chat.png`);
  while (layout === "phone" && !app.texts().includes("Communities")) {
    await app.press("Back >> nth=0");
    await pause(300);
  }
  await app.press("label:Communities >> nth=0");
  await pause(400);
  await app.screenshot(`${tag}-communities.png`);
  await app.press("label:You >> nth=0");
  await pause(400);
  await app.screenshot(`${tag}-you.png`);
  await app.press("Notifications >> nth=0").catch(() => {});
  await pause(600);
  await app.screenshot(`${tag}-switches.png`);
  if (layout === "phone") {
    await app.press("Back >> nth=0").catch(() => {});
    await pause(400);
  }
  await app.press("Help and feedback").catch(() => {});
  await pause(450);
  await app.scroll("text:Popular articles", 3000).catch(() => {});
  await pause(300);
  await app.press("label:UI gallery >> nth=0").catch(() => {});
  await app.waitFor("text:Buttons", { timeout: 20000 }).catch(() => {});
  await pause(500);
  await app.screenshot(`${tag}-gallery-0.png`);
  await app.scroll("text:Buttons", layout === "phone" ? 620 : 560).catch(() => {});
  await pause(350);
  await app.screenshot(`${tag}-gallery-1.png`);
  await app.scroll("text:Buttons", layout === "phone" ? 620 : 560).catch(() => {});
  await pause(350);
  await app.screenshot(`${tag}-gallery-2.png`);
  const step = layout === "phone" ? 620 : 560;
  await app.scroll("text:Buttons", -20000).catch(() => {});
  await app.scroll("text:Buttons", step * 5 + 300).catch(() => {});
  await pause(300);
  await app.press("Open sheet…").catch(() => {});
  await pause(700);
  await app.screenshot(`${tag}-sheet.png`);
  app.dispose();
}

for (const layout of ["desktop", "phone"] as const) {
  for (const scheme of ["light", "dark"] as const) {
    test(`skin ${layout} ${scheme}`, async () => {
      await run(layout, scheme);
    }, 180000);
  }
}
