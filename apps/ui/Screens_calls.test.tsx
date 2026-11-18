// Screenshots of the call screens (A8) on macOS, desktop and phone sizes,
// light and dark: `nsh test Screens_calls.test.tsx --target macos`.
// Output in shots/calls-*.png. The calls are the mock's (no media).
import { open, test } from "nsh/test";

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("call screens", async () => {
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
        await app.screenshot(`shots/debug-retry-${i}.png`);
      }
    }
  };
  const shot = async (name: string) => {
    await pause(450);
    await app.screenshot(`shots/calls-${name}.png`);
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
