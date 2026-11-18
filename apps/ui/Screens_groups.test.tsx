// A6/A7 screens on macOS at desktop and phone sizes:
// `nsh test Screens_groups.test.tsx --target macos`. Output in shots/groups-*.png.
// Desktop (1180×780) and phone (390×844) in light and dark.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
    await app.screenshot(`shots/groups-${tag}-${name}.png`);
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
  const openChat = async (name: string) => {
    await tab("Chats");
    await pick(name);
    await pause(300);
    await app.press("Chat info");
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
  await app.press("Chat info");
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
  await app.press("Stickers and packs");
  await shot("24-packs");
  await app.type("Pack link", "https://songbird.chat/pack/ab12cd#k3y-long-enough");
  await app.press("Add");
  await pause(500);
  await shot("25-packs-installing");
  app.dispose();
}

test("desktop light", () => run(false, false), 300000);
test("desktop dark", () => run(false, true), 300000);
test("phone light", () => run(true, false), 300000);
test("phone dark", () => run(true, true), 300000);
