// Prompt 10 (backups, M5): the screens that became real, light and dark, desktop and phone.
//   nsh test Screens_backups.test.tsx            (headless)
//   nsh test Screens_backups.test.tsx --target macos   (screenshots in shots/backups/)
// Two app instances move a history to each other through the transfer screens.
import { expect, open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** A screenshot under `--target`; headless runs check the behaviour only. */
async function snap(app: any, path: string) {
  try {
    await app.screenshot(path);
  } catch (e: any) {
    if (!String(e?.message ?? e).includes("needs a real platform")) throw e;
  }
}
const DESKTOP: [number, number] = [1180, 780];
const PHONE: [number, number] = [390, 844];
type Scheme = "light" | "dark";
const tagOf = (size: [number, number], scheme: Scheme) => `${size[0] > 700 ? "d" : "p"}-${scheme}`;

async function fresh(size: [number, number], scheme: Scheme) {
  const app = await open(".", { storage: {}, colorScheme: scheme });
  await app.setViewport(size[0], size[1]);
  await pause(600);
  return app;
}

const combos: [[number, number], Scheme][] = [
  [DESKTOP, "light"],
  [DESKTOP, "dark"],
  [PHONE, "light"],
  [PHONE, "dark"],
];

for (const [size, scheme] of combos) {
  const t = tagOf(size, scheme);

  test(`backup destinations and fields ${t}`, async () => {
    const app = await fresh(size, scheme);
    const shot = (n: string) => snap(app, `shots/backups/${t}-${n}.png`);
    await app.keyboard.press("mod+alt+4");
    await pause(800);
    await app.press("Set up backups");
    await pause(500);
    await app.press("Continue");
    await pause(500);
    // Clouds Songbird can't sign in to yet say so.
    expect(app.texts().some((x: string) => x.startsWith("Coming soon"))).toBe(true);
    await shot("where");
    await app.press("S3 bucket");
    await pause(400);
    await app.scroll("Secret access key", 400);
    await pause(300);
    await shot("s3-fields");
    await app.press("Nextcloud (WebDAV)");
    await pause(400);
    await app.scroll("App password", 400);
    await pause(300);
    await shot("nextcloud-fields");
  }, 120_000);

  test(`restore refuses a mistyped key ${t}`, async () => {
    const app = await fresh(size, scheme);
    if (!app.texts().includes("Get started")) return;
    const shot = (n: string) => snap(app, `shots/backups/${t}-${n}.png`);
    await app.press("I already have an account");
    await pause(400);
    await app.press("Restore from a backup");
    await pause(500);
    await app.type("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-…", "SB4K7Q2MXN8P3HVAR9TELW6CJD5F2KBGSB4K7Q2MXN8P3HVAR9TELW6CJD5F2KBG");
    await pause(300);
    expect(app.texts().some((x: string) => x.startsWith("That key doesn't check out"))).toBe(true);
    await shot("restore-typo");
    // This device's own backup, made with the debug shortcut, restores for real.
    await app.keyboard.press("mod+alt+b");
    await pause(5000);
    await app.press("Restore");
    await pause(6000);
    expect(app.texts()).toContain("Your chats are back");
    await shot("restore-done");
  }, 120_000);
}

test("two app instances move a history through the transfer screens", async () => {
  const newPhone = await fresh(PHONE, "light");
  const oldPhone = await fresh(PHONE, "dark");
  await newPhone.keyboard.press("mod+alt+6");
  await oldPhone.keyboard.press("mod+alt+6");
  await pause(700);
  await newPhone.press("This is my new phone");
  await pause(1500);
  await snap(newPhone, "shots/backups/transfer-new-code.png");
  await newPhone.press("Copy code");
  const code = newPhone.clipboard();
  expect(code?.startsWith("songbird-transfer:")).toBe(true);
  await oldPhone.press("This is my old phone");
  await pause(700);
  await snap(oldPhone, "shots/backups/transfer-old-scan.png");
  await oldPhone.type("label:songbird-transfer:…", code!);
  await oldPhone.press("Connect");
  await pause(2500);
  expect(oldPhone.texts()).toContain("Do both phones show this code?");
  expect(newPhone.texts()).toContain("Does your old phone show this code?");
  // Both show the same six digits.
  const digits = (app: any) => app.texts().find((x: string) => /^\d{3} \d{3}$/.test(x));
  expect(digits(oldPhone)).toBe(digits(newPhone));
  await snap(oldPhone, "shots/backups/transfer-old-compare.png");
  await snap(newPhone, "shots/backups/transfer-new-compare.png");
  await oldPhone.press("They match");
  await pause(3000);
  // The new phone answers and applies nothing until its user confirms too.
  expect(newPhone.texts()).not.toContain("Transfer complete");
  await newPhone.press("They match");
  await pause(12000);
  expect(oldPhone.texts()).toContain("Transfer complete");
  expect(newPhone.texts()).toContain("Transfer complete");
  await snap(newPhone, "shots/backups/transfer-new-done.png");
  await snap(oldPhone, "shots/backups/transfer-old-done.png");
}, 240_000);
