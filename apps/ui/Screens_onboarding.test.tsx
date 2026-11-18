// Screenshots of onboarding, identity and devices, and backups (A4, A11):
// `nsh test Screens_onboarding.test.tsx --target macos`. Output in shots/.
// Each test opens the app on fresh storage, so the first run shows.
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const DESKTOP: [number, number] = [1180, 780];
const PHONE: [number, number] = [390, 844];

async function fresh(size: [number, number], scheme: "light" | "dark" = "light") {
  const app = await open(".", { storage: {}, colorScheme: scheme });
  await app.setViewport(size[0], size[1]);
  await pause(600);
  return app;
}

async function newUser(prefix: string, size: [number, number], scheme: "light" | "dark") {
  const app = await fresh(size, scheme);
  const shot = (name: string) => app.screenshot(`shots/onboarding-${prefix}-${name}.png`);
  await shot("01-welcome");
  await app.press("Page 3 of 3");
  await pause(400);
  await shot("02-welcome-3");
  await app.press("Get started");
  await pause(500);
  await shot("03-invite");
  await app.type("Invite code", "usedcode");
  await app.press("Continue");
  await pause(1100);
  await shot("04-invite-refused");
  await app.clear("Invite code");
  await app.type("Invite code", "K7P2QX9M");
  await app.press("Continue");
  await pause(1200);
  await app.type("e.g. ana.popescu", "ana");
  await pause(900);
  await shot("05-username-taken");
  await app.clear("e.g. ana.popescu");
  await app.type("e.g. ana.popescu", "radu.d");
  await pause(900);
  await shot("06-username-available");
  await app.press("Continue");
  await pause(400);
  await shot("07-creating");
  await pause(1800);
  await app.type("First and last name, or a nickname", "Radu Diaconu");
  await pause(300);
  await shot("08-profile");
  await app.press("Continue");
  await pause(500);
  await shot("09-recovery");
  await app.type("Last 4 characters", "2KBG");
  await pause(300);
  await shot("10-recovery-confirmed");
  await app.press("Continue");
  await pause(500);
  await shot("11-backup-offer");
  await app.press("Set up backups");
  await pause(500);
  await app.press("Continue");
  await pause(500);
  await shot("12-backup-where");
  await app.press("Continue");
  await pause(500);
  await shot("13-backup-options");
  await app.press("Turn on backups");
  await pause(500);
  await shot("14-backup-done");
  await app.press("Done");
  await pause(500);
  await shot("15-notifications");
  await app.press("Not now");
  await pause(500);
  await shot("16-connect");
  await app.press("Share an invite link");
  await pause(500);
  await shot("17-connect-invite");
  await app.press("Scan a friend's QR code");
  await pause(600);
  await shot("18-connect-scan");
  await pause(2800);
  await shot("19-connect-found");
  await app.press("Create a group and share its link");
  await pause(500);
  await shot("20-connect-group");
  await app.press("Start chatting");
  await pause(900);
  await shot("21-finished");
}

test("new user, desktop, light", async () => {
  await newUser("d", DESKTOP, "light");
}, 120_000);

test("new user, phone, dark", async () => {
  await newUser("p", PHONE, "dark");
}, 120_000);

async function returningUser(prefix: string, size: [number, number], scheme: "light" | "dark") {
  const app = await fresh(size, scheme);
  const shot = (name: string) => app.screenshot(`shots/onboarding-${prefix}-${name}.png`);
  await app.press("I already have an account");
  await pause(500);
  await shot("r1-returning");
  await app.press("Restore from a backup");
  await pause(500);
  await app.type("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", "SB4K7Q2MXN8P3HVAR9TELW6CJD5F2KBG");
  await pause(300);
  await shot("r2-restore-key");
  await app.press("Try a damaged backup (preview)");
  await pause(1300);
  await shot("r3-restore-running");
  await pause(1500);
  await shot("r4-restore-failed");
  await app.press("Try again");
  await pause(500);
  await app.press("Restore");
  await pause(2600);
  await shot("r5-restore-progress");
  await pause(2400);
  await shot("r6-restore-done");
  await app.press("Back");
  await pause(400);
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

test("returning user, desktop, dark", async () => {
  await returningUser("d", DESKTOP, "dark");
}, 120_000);

test("returning user, phone, light", async () => {
  await returningUser("p", PHONE, "light");
}, 120_000);

// The pages devices and backups own, reached through the debug-only
// preview keys of the first run (mod+alt+1 … 7).
async function page(key: string, name: string, size: [number, number], scheme: "light" | "dark", then?: (app: any, shot: (n: string) => Promise<unknown>) => Promise<void>) {
  const app = await fresh(size, scheme);
  const prefix = size[0] > 700 ? "d" : "p";
  const shot = (n: string) => app.screenshot(`shots/devices-${prefix}-${n}.png`);
  await app.keyboard.press(key);
  await pause(900);
  await shot(name);
  if (then) await then(app, shot);
}

for (const [size, scheme] of [[DESKTOP, "light"], [PHONE, "dark"]] as const) {
  const tag = `${size[0] > 700 ? "desktop" : "phone"}, ${scheme}`;
  test(`safety number, ${tag}`, async () => {
    await page("mod+alt+1", "safety", size, scheme, async (app, shot) => {
      await app.press("Scan code");
      await pause(700);
      await shot("safety-scan");
      await pause(2200);
      await shot("safety-match");
    });
  }, 120_000);
  test(`safety number changed, ${tag}`, async () => {
    await page("mod+alt+7", "safety-changed", size, scheme);
  }, 120_000);
  test(`linked devices, ${tag}`, async () => {
    await page("mod+alt+2", "linked", size, scheme, async (app, shot) => {
      await app.press("Link a device");
      await pause(700);
      await shot("linked-link");
      await pause(3000);
      await shot("linked-added");
      await app.press("MacBook Air");
      await pause(700);
      await shot("linked-device");
    });
  }, 120_000);
  test(`account security, ${tag}`, async () => {
    await page("mod+alt+3", "account", size, scheme, async (app, shot) => {
      await app.scroll("Username link", 500);
      await pause(300);
      await shot("account-2");
      await app.press("Switch accounts");
      await pause(700);
      await shot("account-switcher");
    });
  }, 120_000);
  test(`backups, ${tag}`, async () => {
    await page("mod+alt+4", "backups-off", size, scheme, async (app, shot) => {
      await app.press("Set up backups");
      await pause(600);
      await shot("backups-wizard-why");
      await app.press("Continue");
      await pause(500);
      await app.press("Nextcloud (WebDAV)");
      await pause(500);
      await shot("backups-wizard-nextcloud");
      await app.press("Songbird servers");
      await app.press("Continue");
      await pause(500);
      await shot("backups-wizard-key");
      await app.type("Last 4 characters", "2KBG");
      await app.press("Continue");
      await pause(500);
      await app.press("Turn on backups");
      await pause(500);
      await app.press("Done");
      await pause(900);
      await shot("backups-on-running");
      await pause(2500);
      await shot("backups-on");
      await app.press("Show a full-storage problem");
      await pause(500);
      await shot("backups-problem");
    });
  }, 120_000);
  test(`transfer, ${tag}`, async () => {
    await page("mod+alt+6", "transfer", size, scheme, async (app, shot) => {
      await app.press("This is my new phone");
      await pause(700);
      await shot("transfer-code");
      await pause(3600);
      await shot("transfer-moving");
      await pause(3500);
      await shot("transfer-done");
    });
  }, 120_000);
}
