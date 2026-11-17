// Polish pass screenshots for the chat list and the conversation:
// `SONGBIRD_ONBOARDED=1 nsh test Polish_conv.test.tsx --target macos`.
// Output in shots/pc/<TAG>-*.png.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const TAG = "now";

async function step(name: string, f: () => Promise<void>) {
  try {
    await f();
  } catch (e) {
    console.log(`step ${name} failed: ${String(e).slice(0, 300)}`);
  }
}

async function start(w: number, h: number, scheme: "light" | "dark") {
  const app = await open(".");
  await app.setColorScheme(scheme);
  await app.setViewport(w, h);
  await pause(500);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  const shot = async (name: string) => {
    await pause(600);
    await app.screenshot(`shots/pc/${TAG}-${name}.png`);
  };
  return { app, shot };
}

const BUDGET = "text:/^Can you send me the updated budget/";

for (const scheme of ["light", "dark"] as const) {
  for (const [lay, w, h] of [["d", 1180, 780], ["p", 390, 844]] as const) {
    test(`${lay} ${scheme} list+chat`, async () => {
      const { app, shot } = await start(w, h, scheme);
      await shot(`${lay}-list-${scheme}`);
      await step("list end", async () => {
        await app.scroll("text:Mihai Ionescu", 3000);
        await shot(`${lay}-listend-${scheme}`);
        await app.scroll("text:Mihai Ionescu", -3000);
      });
      await step("ana", async () => {
        await app.press("text:Ana Popescu");
        await shot(`${lay}-ana-${scheme}`);
        await app.scroll("label:Messages", -1200);
        await shot(`${lay}-ana2-${scheme}`);
        await app.scroll("label:Messages", -1200);
        await shot(`${lay}-ana3-${scheme}`);
      });
    }, 120000);

    test(`${lay} ${scheme} menu`, async () => {
      const { app, shot } = await start(w, h, scheme);
      await step("menu", async () => {
        await app.press("text:Ana Popescu");
        await pause(600);
        if (lay === "d") await app.rightClick(BUDGET);
        else await app.longPress(BUDGET);
        await shot(`${lay}-menu-${scheme}`);
        await app.press("label:Message info");
        await shot(`${lay}-msginfo-${scheme}`);
        await app.press("label:Back");
        await pause(500);
      });
      await step("select", async () => {
        if (lay === "d") await app.rightClick(BUDGET);
        else await app.longPress(BUDGET);
        await pause(400);
        await app.press("label:Select");
        await pause(300);
        await app.press("label:Select message >> nth=1");
        await shot(`${lay}-select-${scheme}`);
      });
    }, 120000);

    test(`${lay} ${scheme} compose`, async () => {
      const { app, shot } = await start(w, h, scheme);
      await step("open", async () => {
        await app.press("text:Ana Popescu");
        await pause(600);
      });
      await step("attach", async () => {
        await app.press("label:Attach");
        await shot(`${lay}-attach-${scheme}`);
        await app.press("label:Close");
      });
      await step("type", async () => {
        await app.type("id:composer", "Great, thanks! See https://songbird.chat for the details, and the budget too");
        await shot(`${lay}-typed-${scheme}`);
        await app.press("label:Send");
        await pause(2500);
        await shot(`${lay}-sent-${scheme}`);
      });
      await step("info", async () => {
        await app.press("label:Ana Popescu, chat info");
        await shot(`${lay}-info-${scheme}`);
        await app.scroll("text:Media, links and docs", 400);
        await shot(`${lay}-info2-${scheme}`);
      });
    }, 120000);

    test(`${lay} ${scheme} group+10k`, async () => {
      const { app, shot } = await start(w, h, scheme);
      await step("group", async () => {
        await app.press("text:Familia 🏡");
        await shot(`${lay}-group-${scheme}`);
      });
      if (lay === "p") await step("back", async () => app.press("label:Back"));
      await step("10k", async () => {
        await app.type("label:Search chats and messages", "Ioana");
        await pause(500);
        await shot(`${lay}-search-${scheme}`);
        await app.press("text:Ioana Ștefănescu >> nth=0");
        await shot(`${lay}-10k-${scheme}`);
        for (let i = 0; i < 8; i++) {
          await app.scroll("label:Messages", -3000);
          await pause(60);
        }
        await shot(`${lay}-10kup-${scheme}`);
      });
    }, 120000);
  }
}
