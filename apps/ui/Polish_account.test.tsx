// Polish pass screenshots for onboarding, devices, backups and settings.
// Onboarding and the devices/backups pages (preview keys of the first run):
//   nsh test Polish_account.test.tsx --target macos
// Settings (the app past the first run):
//   SONGBIRD_ONBOARDED=1 nsh test Polish_account.test.tsx --target macos
// Output in shots/polish/.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** The last group of the recovery key the screen shows (16 groups of four). */
const lastGroup = (app: any): string => {
  const groups = app.texts().filter((t: string) => /^[0-9A-HJKMNP-TV-Z]{4}$/.test(t));
  return groups[groups.length - 1];
};

const DESKTOP: [number, number] = [1180, 780];
const PHONE: [number, number] = [390, 844];
type Scheme = "light" | "dark";
const tagOf = (size: [number, number], scheme: Scheme) => `${size[0] > 700 ? "d" : "p"}-${scheme}`;

async function fresh(size: [number, number], scheme: Scheme) {
  const app = await open(".", { storage: {}, colorScheme: scheme });
  await app.setViewport(size[0], size[1]);
  await pause(600);
  firstRun(app);
  return app;
}

// Under SONGBIRD_ONBOARDED=1 the first run is skipped: its tests then do nothing.
class Skip extends Error {}
const firstRun = (app: any) => {
  if (!app.texts().includes("Get started")) throw new Skip();
};
const guard = (f: () => Promise<void>) => async () => {
  try {
    await f();
  } catch (e) {
    if (!(e instanceof Skip)) throw e;
  }
};

async function newUser(size: [number, number], scheme: Scheme) {
  const app = await fresh(size, scheme);
  const tag = tagOf(size, scheme);
  const shot = (name: string) => app.screenshot(`shots/polish/ob-${tag}-${name}.png`);
  await shot("01-welcome");
  await app.press("Page 2 of 3");
  await pause(400);
  await shot("02-welcome-2");
  await app.press("Page 3 of 3");
  await pause(400);
  await shot("02-welcome-3");
  await app.press("Get started");
  await pause(500);
  await shot("03-invite");
  await app.type("Invite code", "0000-qx9m-ab3d-eh4j-nr5s-tv6w");
  await pause(300);
  await shot("03b-invite-filled");
  await app.press("Continue");
  await pause(500);
  await app.type("e.g. ana.popescu", "ana..p");
  await pause(300);
  await shot("05-username-problem");
  await app.clear("e.g. ana.popescu");
  await app.type("e.g. ana.popescu", "Ana");
  await pause(300);
  await shot("06-username-ok");
  await app.press("Continue");
  await pause(400);
  await shot("07-creating");
  await pause(1800);
  await shot("04-invite-refused");
  await app.clear("Invite code");
  await app.type("Invite code", "K7P2QX9MAB3DEH4JNR5STV6W");
  await app.press("Continue");
  await pause(500);
  await app.press("Continue");
  await pause(2000);
  await shot("07b-claim-username");
  await app.clear("e.g. ana.popescu");
  await app.type("e.g. ana.popescu", "Radu.D");
  await app.press("Continue");
  await pause(1200);
  await app.type("First and last name, or a nickname", "Radu Diaconu");
  await pause(300);
  await shot("08-profile");
  await app.press("Continue");
  await pause(500);
  await shot("09-recovery");
  await app.type("Last 4 characters", lastGroup(app));
  await pause(300);
  await shot("10-recovery-confirmed");
  await app.press("Continue");
  await pause(500);
  await shot("11-backup-offer");
  // The offer is the backup intro: the wizard starts at the destination.
  await app.press("Set up backups");
  await pause(500);
  await shot("12-backup-where");
  await app.press("Continue");
  await pause(500);
  await shot("13-backup-options");
  await app.press("Back");
  await pause(500);
  await shot("14-backup-back-to-where");
  await app.press("Continue");
  await pause(500);
  await app.press("Turn on backups");
  await pause(500);
  await shot("16-backup-done");
  await app.press("Done");
  await pause(500);
  await shot("17-notifications");
  await app.press("Not now");
  await pause(500);
  await shot("18-connect");
  await app.press("Share an invite link");
  await pause(500);
  await shot("19-connect-invite");
  await app.press("Scan a friend's QR code");
  await pause(3400);
  await shot("20-connect-found");
  await app.press("Start chatting");
  await pause(900);
  await shot("21-finished");
}

async function returningUser(size: [number, number], scheme: Scheme) {
  const app = await fresh(size, scheme);
  const tag = tagOf(size, scheme);
  const shot = (name: string) => app.screenshot(`shots/polish/ob-${tag}-${name}.png`);
  await app.press("I already have an account");
  await pause(500);
  await shot("r1-returning");
  await app.press("Restore from a backup");
  await pause(500);
  // 64 characters with a typo: the key's own check refuses it before anything is fetched.
  await app.type("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-…", "SB4K7Q2MXN8P3HVAR9TELW6CJD5F2KBGSB4K7Q2MXN8P3HVAR9TELW6CJD5F2KBG");
  await pause(300);
  await shot("r2-restore-key");
  // Debug builds only: the damaged-backup path has no button, only a key.
  await app.keyboard.press("mod+alt+d");
  await pause(2800);
  await shot("r4-restore-failed");
  await app.press("Try again");
  await pause(500);
  // Debug builds only: back this device up to its folder and fill in its key.
  await app.keyboard.press("mod+alt+b");
  await pause(4000);
  await app.press("Restore");
  await pause(2600);
  await shot("r5-restore-progress");
  await pause(2400);
  await shot("r6-restore-done");
}

async function linkUser(size: [number, number], scheme: Scheme) {
  const app = await fresh(size, scheme);
  const tag = tagOf(size, scheme);
  const shot = (name: string) => app.screenshot(`shots/polish/ob-${tag}-${name}.png`);
  await app.press("I already have an account");
  await pause(500);
  await app.press("Link to another device");
  await pause(600);
  await shot("r7-link");
  await pause(4500);
  await shot("r8-linked");
  await app.press("Back");
  await pause(400);
  await app.press("I lost my recovery key");
  await pause(500);
  await shot("r9-lost-key");
}

async function page(key: string, name: string, size: [number, number], scheme: Scheme, then?: (app: any, shot: (n: string) => Promise<unknown>) => Promise<void>) {
  const app = await fresh(size, scheme);
  const shot = (n: string) => app.screenshot(`shots/polish/dev-${tagOf(size, scheme)}-${n}.png`);
  await app.keyboard.press(key);
  await pause(900);
  await shot(name);
  if (then) await then(app, shot);
}

const combos: [[number, number], Scheme][] = [
  [DESKTOP, "light"],
  [DESKTOP, "dark"],
  [PHONE, "light"],
  [PHONE, "dark"],
];

{
  for (const [size, scheme] of combos) {
    const t = tagOf(size, scheme);
    test(`new user ${t}`, guard(() => newUser(size, scheme)), 120_000);
    test(`returning ${t}`, guard(() => returningUser(size, scheme)), 120_000);
    test(`link ${t}`, guard(() => linkUser(size, scheme)), 120_000);
    test(`devices ${t}`, guard(async () => {
      await page("mod+alt+1", "safety", size, scheme);
      await page("mod+alt+7", "safety-changed", size, scheme);
      await page("mod+alt+2", "linked", size, scheme, async (app, shot) => {
        await app.press("Link a device");
        await pause(900);
        await shot("linked-link");
      });
      await page("mod+alt+3", "account", size, scheme, async (app, shot) => {
        await app.scroll("Username link", 500);
        await pause(300);
        await shot("account-2");
      });
      await page("mod+alt+4", "backups-off", size, scheme, async (app, shot) => {
        await app.press("Set up backups");
        await pause(600);
        await shot("backups-wizard-why");
        await app.press("Continue");
        await pause(500);
        await shot("backups-wizard-where");
      });
      await page("mod+alt+6", "transfer", size, scheme, async (app, shot) => {
        await app.press("This is my new phone");
        await pause(700);
        await shot("transfer-code");
      });
    }), 240_000);
  }
}

// ---------------------------------------------------------------- settings

const PAGES = [
  "Profile", "Account", "Privacy", "What Songbird can see", "Chats", "Appearance", "Notifications",
  "Storage and data", "Linked devices", "Lists", "Broadcast lists", "Starred messages",
  "Presence and nudges", "Parental controls", "Proxy", "WhatsApp chats", "Subscription",
  "Help and feedback", "Invite a friend", "Server connection",
];
const DESKTOP_ONLY = ["Desktop", "Keyboard shortcuts"];
const sel = (p: string, desktop: boolean) =>
  p === "Profile" ? "Your profile, Radu" : p === "Chats" ? "Chats >> nth=0" : p === "What Songbird can see" ? `${p} >> nth=0` : `${p} >> nth=0`;
const file = (name: string) => name.toLowerCase().replace(/[^a-z]+/g, "-");

{
  for (const [size, scheme] of combos) {
    const desktop = size[0] > 700;
    const t = tagOf(size, scheme);
    test(`settings ${t}`, async () => {
      const app = await open(".", { storage: { onboarded: "1" }, colorScheme: scheme });
      await app.setViewport(size[0], size[1]);
      await pause(500);
      await app.press("You >> nth=0");
      await pause(400);
      await app.screenshot(`shots/polish/set-${t}-you.png`);
      for (const p of desktop ? [...PAGES, ...DESKTOP_ONLY] : PAGES) {
        await app.press(sel(p, desktop));
        await pause(500);
        await app.screenshot(`shots/polish/set-${t}-${file(p)}.png`);
        if (!desktop) {
          await app.press("Back");
          await pause(450);
        }
      }
      // Server connection's technical fields, behind Advanced.
      await app.press("Server connection >> nth=0");
      await pause(500);
      await app.press("Advanced");
      await pause(500);
      await app.screenshot(`shots/polish/set-${t}-server-advanced.png`);
      if (!desktop) {
        await app.press("Back");
        await pause(450);
        await app.scroll("Presence and nudges", 900);
        await pause(300);
        await app.screenshot(`shots/polish/set-${t}-you-2.png`);
      }
    }, 240_000);
  }
}
