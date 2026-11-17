// A5 conversation screenshots: `nsh test Screens_chat.test.tsx --target macos`.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function start(w: number, h: number, scheme: "light" | "dark" = "light") {
  const app = await open(".");
  await app.setColorScheme(scheme);
  await app.setViewport(w, h);
  await pause(400);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  return app;
}

test("desktop: Ana, every type, menu, info", async () => {
  const app = await start(1180, 780);
  await app.press("Ana Popescu");
  await pause(700);
  await app.screenshot("shots/chat-desktop-ana.png");
  await app.scroll("Messages", -700);
  await pause(400);
  await app.screenshot("shots/chat-desktop-ana-2.png");
  await app.scroll("Messages", -900);
  await pause(400);
  await app.screenshot("shots/chat-desktop-ana-3.png");
  await app.scroll("Messages", 4000);
  await pause(400);
  await app.rightClick("Can you send me the updated budget before 3?");
  await pause(500);
  await app.screenshot("shots/chat-desktop-menu.png");
  await app.press("Message info");
  await pause(600);
  await app.screenshot("shots/chat-desktop-message-info.png");
});

test("desktop: attach, reply, send, chat info", async () => {
  const app = await start(1180, 780);
  await app.press("Ana Popescu");
  await pause(600);
  await app.press("Attach");
  await pause(600);
  await app.screenshot("shots/chat-desktop-attach.png");
  await app.press("Close");
  await pause(400);
  await app.rightClick("Yes! Finishing it now");
  await pause(300);
  await app.press("Reply");
  await pause(300);
  await app.type("Message", "Great, *thanks*! See https://songbird.chat");
  await pause(300);
  await app.screenshot("shots/chat-desktop-reply.png");
  await app.press("Send");
  await pause(2600);
  await app.screenshot("shots/chat-desktop-sent.png");
  await app.press("Ana Popescu, chat info");
  await pause(600);
  await app.screenshot("shots/chat-desktop-info.png");
});

test("desktop: group, failed, 10k, dark", async () => {
  const app = await start(1180, 780);
  await app.press("Familia 🏡");
  await pause(700);
  await app.screenshot("shots/chat-desktop-group.png");
  await app.press("Ioana Ștefănescu");
  await pause(900);
  await app.screenshot("shots/chat-desktop-10k.png");
  for (let i = 0; i < 8; i++) {
    await app.scroll("Messages", -3000);
    await pause(80);
  }
  await pause(500);
  await app.screenshot("shots/chat-desktop-10k-scrolled.png");
  await app.setColorScheme("dark");
  await app.press("Mihai Ionescu");
  await pause(700);
  await app.screenshot("shots/chat-desktop-mihai-dark.png");
});

test("phone: Ana, menu, attach, info", async () => {
  const app = await start(390, 844);
  await app.press("Ana Popescu");
  await pause(900);
  await app.screenshot("shots/chat-phone-ana.png");
  await app.scroll("Messages", -700);
  await pause(400);
  await app.screenshot("shots/chat-phone-ana-2.png");
  await app.scroll("Messages", 4000);
  await pause(400);
  await app.longPress("Can you send me the updated budget before 3?");
  await pause(600);
  await app.screenshot("shots/chat-phone-menu.png");
  await app.press("Close menu");
  await pause(300);
  await app.press("Attach");
  await pause(700);
  await app.screenshot("shots/chat-phone-attach.png");
  await app.press("Close");
  await pause(500);
  await app.press("Ana Popescu, chat info");
  await pause(800);
  await app.screenshot("shots/chat-phone-info.png");
});

test("phone: group dark", async () => {
  const app = await start(390, 844, "dark");
  await app.press("Familia 🏡");
  await pause(900);
  await app.screenshot("shots/chat-phone-group-dark.png");
});
