// Polish pass, foundations: the shell's four tabs and the ui gallery, desktop
// and phone, light and dark. `SONGBIRD_ONBOARDED=1 nsh test Polish_core.test.tsx --target macos`.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const only = process.env.POLISH_ONLY ?? "";

async function run(layout: "desktop" | "phone", scheme: "light" | "dark") {
  const app = await open(".", { storage: { onboarded: "1" }, colorScheme: scheme });
  await pause(300);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  await app.setColorScheme(scheme);
  if (layout === "phone") await app.setViewport(390, 844);
  else await app.setViewport(1180, 780);
  await pause(500);
  const tag = `${layout}-${scheme}`;
  for (const t of ["Chats", "Calls", "Communities", "You"]) {
    await app.press(`label:${t} >> nth=0`);
    await pause(450);
    await app.screenshot(`shots/polish-core-${tag}-tab-${t.toLowerCase()}.png`);
  }
  if (only === "shell") {
    app.dispose();
    return;
  }
  await app.press("Help and feedback");
  await pause(450);
  await app.press("UI gallery");
  await app.waitFor("text:BUTTONS", { timeout: 20000 });
  await pause(500);
  await app.screenshot(`shots/polish-core-${tag}-gallery-0.png`);
  const step = layout === "phone" ? 620 : 560;
  for (let i = 0; i < 9; i++) {
    await app.scroll("text:BUTTONS", step).catch(() => {});
    await pause(350);
    await app.screenshot(`shots/polish-core-${tag}-gallery-${i + 1}.png`);
  }
  await app.scroll("text:BUTTONS", -20000).catch(() => {});
  await app.scroll("text:BUTTONS", step * 4 + 300).catch(() => {});
  await app.press("Show toast");
  await pause(450);
  await app.screenshot(`shots/polish-core-${tag}-toast.png`);
  await app.press("Open sheet…");
  await pause(700);
  await app.screenshot(`shots/polish-core-${tag}-sheet.png`);
  app.dispose();
}

for (const layout of ["desktop", "phone"] as const) {
  for (const scheme of ["light", "dark"] as const) {
    const cases = process.env.POLISH_CASES ?? "";
    const t = cases === "" || cases.split(",").includes(`${layout}-${scheme}`) ? test : test.skip;
    t(`core ${layout} ${scheme}`, async () => {
      await run(layout, scheme);
    }, 180000);
  }
}
