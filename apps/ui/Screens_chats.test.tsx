// Screenshots of the chat list (A5) on macOS at desktop and phone sizes,
// light and dark: `nsh test Screens_chats.test.tsx --target macos`.
// Output in shots/chats-*.png.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function step(name: string, f: () => Promise<void>) {
  try {
    await f();
  } catch (e) {
    console.log(`step ${name} failed: ${e}`);
  }
}

async function start(width: number, height: number, scheme: "light" | "dark") {
  const app = await open(".");
  await app.setViewport(width, height);
  await app.setColorScheme(scheme);
  await pause(400);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`shots/chats-${name}.png`);
  };
  const back = async () => {
    await step("back", async () => {
      await app.press("label:Back");
    });
    await pause(300);
  };
  return { app, shot, back };
}

for (const scheme of ["light", "dark"] as const) {
  test(`desktop ${scheme}`, async () => {
    const { app, shot, back } = await start(1180, 780, scheme);
    await shot(`desktop-${scheme}`);
    await step("open chat", async () => {
      await app.press("text:Mihai Ionescu");
    });
    await shot(`desktop-open-${scheme}`);
    await step("menu", async () => {
      await app.rightClick("text:Design team");
      await shot(`desktop-menu-${scheme}`);
      await app.press("text:Add to list");
      await shot(`desktop-menu-lists-${scheme}`);
    });
    await step("pin via menu", async () => {
      await app.press("text:Pin chat");
      await shot(`desktop-pinned-${scheme}`);
    });
    await step("archived", async () => {
      await app.press("text:Archived");
      await shot(`desktop-archived-${scheme}`);
    });
    await back();
    await step("requests", async () => {
      await app.press("text:Message requests");
      await shot(`desktop-requests-${scheme}`);
    });
    await back();
    await step("search", async () => {
      await app.type("label:Search chats and messages", "an");
      await shot(`desktop-search-${scheme}`);
      await app.clear("label:Search chats and messages");
    });
    await step("new chat", async () => {
      await app.press("label:New chat");
      await shot(`desktop-new-${scheme}`);
    });
    await back();
    await step("lists", async () => {
      await app.press("label:Manage chat lists");
      await shot(`desktop-lists-${scheme}`);
    });
  }, 120000);

  test(`phone ${scheme}`, async () => {
    const { app, shot, back } = await start(390, 844, scheme);
    await shot(`phone-${scheme}`);
    await step("unread chip", async () => {
      await app.press("label:Unread");
      await shot(`phone-unread-${scheme}`);
      await app.press("label:Channels");
      await shot(`phone-channels-${scheme}`);
      await app.press("label:Favourites");
      await shot(`phone-favourites-${scheme}`);
      await app.press("label:All");
    });
    await step("phone hold", async () => {
      await app.longPress("text:Familia");
      await shot(`phone-hold-${scheme}`);
    });
    await step("phone right click", async () => {
      await app.rightClick("text:Mama");
      await shot(`phone-menu-${scheme}`);
      await app.press("text:Mark as unread");
      await shot(`phone-marked-${scheme}`);
    });
    await step("phone requests", async () => {
      await app.press("text:Message requests");
      await shot(`phone-requests-${scheme}`);
    });
    await back();
    await step("phone archived", async () => {
      await app.press("text:Archived");
      await shot(`phone-archived-${scheme}`);
    });
    await back();
    await step("phone search", async () => {
      await app.type("label:Search chats and messages", "budget");
      await shot(`phone-search-${scheme}`);
      await app.clear("label:Search chats and messages");
      await app.type("label:Search chats and messages", "qqqz");
      await shot(`phone-search-empty-${scheme}`);
      await app.clear("label:Search chats and messages");
    });
    await step("phone new chat", async () => {
      await app.press("label:New chat");
      await shot(`phone-new-${scheme}`);
    });
    await back();
  }, 120000);
}
