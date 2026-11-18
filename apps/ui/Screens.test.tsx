// Screenshots of the merged app on macOS: `SONGBIRD_ONBOARDED=1 nsh test
// Screens.test.tsx --target macos` (the first run has its own tests).
// Output in shots/app-*.png.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function tour(w: number, h: number, tag: string) {
  const app = await open(".");
  await app.setViewport(w, h);
  await pause(500);
  await app.screenshot(`shots/app-${tag}-chats.png`);
  await app.press("Ana Popescu >> nth=0");
  await pause(600);
  await app.screenshot(`shots/app-${tag}-chat.png`);
  await app.press("Ana Popescu, chat info >> nth=0").catch(() => {});
  await pause(500);
  await app.screenshot(`shots/app-${tag}-chat-info.png`);
  // Back to the tabs (phones pushed the chat over them).
  while (!app.texts().includes("Communities")) {
    await app.press("Back >> nth=0");
    await pause(300);
  }
  for (const t of ["Calls", "Communities", "You"]) {
    await app.press(`${t} >> nth=0`);
    await pause(300);
    await app.screenshot(`shots/app-${tag}-${t.toLowerCase()}.png`);
  }
  return app;
}

test("desktop", async () => {
  const app = await tour(1180, 780, "desktop");
  await app.press("You >> nth=0");
  await pause(300);
  await app.press("Server connection >> nth=0");
  await pause(400);
  await app.screenshot("shots/app-desktop-server.png");
});

test("phone", async () => {
  await tour(390, 844, "phone");
});
