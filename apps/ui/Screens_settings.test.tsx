// Screenshots of the You tab and settings pages on macOS, desktop and
// phone sizes, light and dark: `nsh test Screens_settings.test.tsx --target macos`.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

const pages = ["Profile", "Privacy", "What Songbird can see", "Chats", "Appearance", "Notifications", "Parental controls"];
const sel = (p: string, desktop: boolean) =>
  p === "Profile" ? "Your profile, Radu" : p === "Chats" ? "Chats >> nth=0" : p === "What Songbird can see" ? `${p} >> nth=0` : p;
const file = (name: string) => name.toLowerCase().replace(/[^a-z]+/g, "-");

async function start(scheme: "light" | "dark") {
  const app = await open(".", { storage: { onboarded: "1" }, colorScheme: scheme });
  await pause(300);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  return app;
}

async function themes(app: any, prefix: string) {
  await app.press("Light");
  await pause(400);
  await app.screenshot(`shots/settings-${prefix}-appearance-light.png`);
  await app.press("High contrast");
  await pause(400);
  await app.screenshot(`shots/settings-${prefix}-appearance-hc.png`);
  await app.press("Dark");
  await pause(400);
  await app.screenshot(`shots/settings-${prefix}-appearance-dark.png`);
  await app.press("System");
  await pause(300);
}

test("settings desktop", async () => {
  const app = await start("light");
  await app.setViewport(1180, 780);
  await pause(300);
  await app.press("You");
  await pause(300);
  await app.screenshot("shots/settings-desktop-you.png");
  for (const p of pages) {
    await app.press(sel(p, true));
    await pause(400);
    await app.screenshot(`shots/settings-desktop-${file(p)}.png`);
    if (p === "Appearance") await themes(app, "desktop");
  }
  await app.press("Set a status");
  await pause(500);
  await app.screenshot("shots/settings-desktop-status-sheet.png");
});

test("settings phone", async () => {
  const app = await start("light");
  await app.setViewport(390, 844);
  await pause(300);
  await app.press("You");
  await pause(300);
  await app.screenshot("shots/settings-phone-you.png");
  for (const p of pages) {
    await app.press(sel(p, false));
    await pause(500);
    await app.screenshot(`shots/settings-phone-${file(p)}.png`);
    if (p === "Appearance") await themes(app, "phone");
    await app.press("Back");
    await pause(400);
  }
});

test("settings dark", async () => {
  const app = await start("dark");
  await app.setViewport(1180, 780);
  await pause(300);
  await app.press("You");
  await pause(300);
  await app.screenshot("shots/settings-dark-you.png");
  for (const p of ["Privacy", "What Songbird can see", "Chats"]) {
    await app.press(sel(p, true));
    await pause(400);
    await app.screenshot(`shots/settings-dark-${file(p)}.png`);
  }
});
