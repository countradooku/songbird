// Polish pass screenshots (groups, media, calls): desktop + phone, light + dark.
// `SONGBIRD_ONBOARDED=1 nsh test Polish_people.test.tsx --target macos`; output in shots/people/.
// Set ONLY to "groups" or "calls" below to run one half; TAG prefixes the files.
import { open, test } from "nsh/test";

const ONLY: string = "";
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const only = ONLY;
const TAG = "f";

async function run(phone: boolean, dark: boolean) {
  const app = await open(".");
  const tag = `${phone ? "phone" : "desktop"}${dark ? "-dark" : ""}`;
  if (phone) await app.setViewport(390, 844);
  else await app.setViewport(1180, 780);
  await app.setColorScheme(dark ? "dark" : "light");
  await pause(400);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`shots/people/${TAG}-groups-${tag}-${name}.png`);
  };
  const tab = async (name: string) => {
    // Phones: go back to the tab bar first.
    for (let i = 0; i < 8 && app.count(`role:button[${name}]`) === 0 && app.count("Back") > 0; i++) {
      await app.press(`Back >> nth=${app.count("Back") - 1}`);
      await pause(350);
    }
    await app.press(`role:button[${name}]`);
    await pause(250);
  };
  // The detail pane can repeat a list pane's row: press the last one.
  const pick = async (label: string) => {
    const n = app.count(label);
    await app.press(n > 1 ? `${label} >> nth=${n - 1}` : label);
    await pause(300);
  };
  const back = async () => {
    await app.press("Back");
    await pause(300);
  };
  // The chat header's menu opens the info (the header press is a pointer
  // gesture the test driver does not reach).
  const groupInfo = async () => {
    const n = app.count("label:More options");
    await app.press(`label:More options >> nth=${n - 1}`);
    await pause(300);
    await app.press("Group info");
    await pause(400);
  };
  const openChat = async (name: string) => {
    await tab("Chats");
    await pick(name);
    await pause(300);
    await groupInfo();
    await pause(300);
  };

  // Communities tab and a community's home.
  await tab("Communities");
  await shot("01-communities");
  await pick("Cluj Climbers");
  await shot("02-community-home");

  // Weekend trips: the user is a Member.
  await pick("Weekend trips");
  await pause(300);
  await groupInfo();
  await shot("03-info-member");
  await app.press("Group permissions");
  await shot("04-roles-member");

  // Design team: the user is an Admin.
  await openChat("Design team");
  await shot("05-info-admin");
  await app.press("Group permissions");
  await shot("06-roles-admin");
  await back();
  await app.press("Invite via link");
  await shot("07-invite-link");
  await back();
  await app.press("Join requests");
  await shot("08-join-requests");
  await back();
  await app.press("View member changes");
  await shot("09-member-changes");
  await back();
  await app.press("Ana Popescu, Owner");
  await shot("10-member-sheet");
  await app.press("Close");
  await pause(300);

  // Familia: the user is the Owner; media and the viewer.
  await openChat("Familia 🏡");
  await shot("11-info-owner");
  await app.press("Media, links and docs");
  await shot("12-media");
  await app.press("Photo: A snow-covered garden at dawn");
  await shot("13-viewer");
  await app.press("Close");
  await pause(300);

  // New group flow.
  await tab("Communities");
  await pick("Cluj Climbers");
  await pause(300);
  await pick("Add group");
  await shot("14-add-group-sheet");
  await pick("Create new group");
  await pause(400);
  await shot("15-new-group-members");
  await app.press("Ana Popescu");
  await app.press("Mihai Ionescu");
  await app.press("Sofia Martínez");
  await shot("16-new-group-picked");
  await app.press("Next: 3 people");
  await pause(300);
  await app.type("Group name", "Bouldering Tuesdays");
  await shot("17-new-group-details");
  await app.press("Create group");
  await shot("18-share-invite");
  await pick("Open group");
  await pause(300);
  await shot("19-new-group-opened");

  // Find channels.
  await tab("Communities");
  await pick("Find channels");
  await shot("20-find-channels");

  // Storage and data, packs.
  await tab("You");
  await app.press("Storage and data");
  await shot("21-storage-data");
  await app.press("Manage storage");
  await shot("22-manage-storage");
  await pick("Design team");
  await pause(300);
  await app.press("Select all");
  await shot("23-chat-storage");
  await tab("You");
  // You → Chats (the settings row: before the tab bar on phones, after the rail on desktops).
  await app.press("Chats >> nth=" + (phone ? 0 : app.count("Chats") - 1));
  await pause(300);
  await app.press("Stickers and packs");
  await shot("24-packs");
  await app.type("Pack link", "https://songbird.chat/pack/ab12cd#k3y-long-enough");
  await app.press("Add");
  await pause(500);
  await shot("25-packs-installing");
  app.dispose();
}

if (only !== "calls") test("desktop light", () => run(false, false), 300000);
if (only !== "calls") test("desktop dark", () => run(false, true), 300000);
if (only !== "calls") test("phone light", () => run(true, false), 300000);
if (only !== "calls") test("phone dark", () => run(true, true), 300000);

if (only !== "groups") test("call screens", async () => {
  const app = await open(".");
  await app.setViewport(1180, 780);
  await pause(400);
  if (app.texts().includes("Get started")) {
    await app.press("Get started");
    await pause(300);
  }
  // A press that first scrolls a row into view can land mid-scroll: try again.
  const ring = async (row: string, expect: string) => {
    await app.scroll("label:Call history", 3000).catch(() => {});
    for (let i = 0; i < 3 && !app.shows(expect); i++) {
      await app.press(row);
      await pause(700);
      if (!app.shows(expect)) {
        console.log("retry", row, i);
        await app.screenshot(`shots/people/debug-retry-${i}.png`);
      }
    }
  };
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`shots/people/${TAG}-calls-${name}.png`);
  };

  for (const scheme of ["light", "dark"] as const) {
    await app.setColorScheme(scheme);
    await app.setViewport(1180, 780);
    await pause(300);
    const d = `desktop-${scheme}`;
    await app.press("label:Calls");
    await shot(`${d}-tab`);

    // Call link sheet.
    await app.press("Create call link");
    await shot(`${d}-link-sheet`);
    await app.type("text:Call name", "Friday catch-up");
    await app.press("Create link");
    await shot(`${d}-link-created`);
    await app.press("label:Close");
    await pause(400);

    // Outgoing voice call: the microphone explainer first (once).
    await app.press("label:Voice call Mihai Ionescu");
    if (app.texts().includes("Songbird needs your microphone for calls")) {
      await shot(`${d}-permission`);
      await app.press("Continue");
    }
    await pause(1300);
    await shot(`${d}-ringing`);
    await pause(4200);
    await shot(`${d}-connected-voice`);
    await app.press("label:End-to-end encrypted. Verify this call");
    await shot(`${d}-verify`);
    await app.press("label:Close");
    await pause(400);
    await app.press("label:Turn camera on");
    await shot(`${d}-video`);
    await app.press("label:Share screen");
    await pause(300);
    await app.press("Entire screen");
    await shot(`${d}-sharing`);
    await app.press("label:Audio and video settings");
    await shot(`${d}-devices`);
    await app.press("label:Close");
    await pause(400);
    await app.press("label:Minimise");
    await shot(`${d}-mini`);
    await app.press("label:End call");
    await pause(200);
    await shot(`${d}-ended`);
    await pause(3000);

    // A group calls: the ringing card, then the grid.
    await ring("Test incoming video call", "label:Answer");
    await shot(`${d}-incoming`);
    await app.press("label:Answer");
    await pause(5000);
    await shot(`${d}-group-grid`);
    await app.press("label:Participants, 5");
    await shot(`${d}-participants`);
    await app.press("label:Close");
    await pause(400);
    await app.press("label:Speaker view");
    await shot(`${d}-group-speaker`);
    await app.press("label:End call");
    await pause(3000);

    // Phone.
    const p = `phone-${scheme}`;
    await app.setViewport(390, 844);
    await pause(600);
    await shot(`${p}-tab`);
    await ring("Test incoming call", "label:Accept");
    await shot(`${p}-incoming`);
    await app.press("label:Accept");
    await pause(3000);
    await shot(`${p}-connected-voice`);
    await app.press("label:Camera");
    await shot(`${p}-video`);
    await app.press("label:More");
    await shot(`${p}-more`);
    await app.press("Verify this call");
    await shot(`${p}-verify`);
    await app.press("label:Close");
    await pause(400);
    await app.press("label:Minimise");
    await shot(`${p}-mini`);
    await app.press("label:Return to call with Ana Popescu");
    await pause(400);
    await app.press("label:End");
    await shot(`${p}-ended`);
    await pause(3000);
  }
}, 600000);
