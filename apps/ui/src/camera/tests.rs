//! The camera's states and lifecycle on the real engine, headless, with scripted fakes
//! (D-0110). Each probe has its own fake, so tests run in parallel.

use std::sync::{Arc, LazyLock};

use nsh_core::platform::Lifecycle;
use nsh_engine::{EngineConfig, Root};
use nsh_testing::Headless;
use songbird_camera::{Access, Facing, Lens, Purpose, Unavailable, fake::FakeCamera};

use super::*;

/// A screen with a scanner that can be closed, listing the codes it read and its state.
fn scan_probe(cam: &FakeCamera) -> impl IntoElement {
    install(Some(Arc::new(cam.clone())), false);
    let open = signal(true);
    let codes = signal(Vec::<String>::new());
    view()
        .child(text(move || format!("codes: {}", codes.get().join(","))))
        .child(button_text("Close", move || open.set(false)))
        .child(
            when(
                move || open.get(),
                move || {
                    let session = use_session(
                        Purpose::ScanCode,
                        || true,
                        move |c| codes.update(|v| v.push(c)),
                    );
                    let shown = session.shown;
                    view()
                        .child(text(move || format!("state: {}", label(&shown.get()))))
                        .child(camera_view(&session, 200.0, "Looking for a code…"))
                },
            )
            .otherwise(|| text("closed")),
        )
}

fn label(s: &Shown) -> String {
    match s {
        Shown::Running(l) => format!("running {l}"),
        other => format!("{other:?}"),
    }
}

fn button_text(label: &'static str, f: impl Fn() + 'static) -> View {
    view()
        .role(AccessibilityRole::Button)
        .label(label)
        .on_press(move || f())
        .child(text(label))
}

fn start<C: Component + 'static>() -> Headless
where
    C::Props: Default,
{
    Headless::start(EngineConfig::new(Root::of::<C>())).expect("the app starts")
}

static GRANTED: LazyLock<FakeCamera> = LazyLock::new(FakeCamera::new);
#[component]
fn GrantedProbe() -> impl IntoElement {
    scan_probe(&GRANTED)
}

#[test]
fn a_scanner_reads_codes_once_and_stops_when_closed() -> Result<(), String> {
    let mut app = start::<GrantedProbe>();
    app.wait_for("text:state: running back")?;
    assert_eq!(GRANTED.running_purposes(), vec![Purpose::ScanCode]);
    GRANTED.show_code("first");
    GRANTED.show_code("first");
    GRANTED.show_code("second");
    app.wait_for("text:codes: first,second")?;
    app.press("Close")?;
    app.wait_for("closed")?;
    assert_eq!(GRANTED.running(), 0, "{:?}", GRANTED.log());
    assert_eq!(GRANTED.log().last().map(String::as_str), Some("stop"));
    Ok(())
}

static BACKGROUND: LazyLock<FakeCamera> = LazyLock::new(FakeCamera::new);
#[component]
fn BackgroundProbe() -> impl IntoElement {
    scan_probe(&BACKGROUND)
}

#[test]
fn the_camera_stops_in_the_background_and_comes_back() -> Result<(), String> {
    let mut app = start::<BackgroundProbe>();
    app.wait_for("text:state: running back")?;
    app.set_environment("background", |e| e.lifecycle = Lifecycle::Background)?;
    app.settle();
    assert_eq!(BACKGROUND.running(), 0, "{:?}", BACKGROUND.log());
    app.set_environment("foreground", |e| e.lifecycle = Lifecycle::Active)?;
    app.wait_for("text:state: running back")?;
    assert_eq!(BACKGROUND.running(), 1);
    assert_eq!(
        BACKGROUND.log(),
        ["open ScanCode back", "stop", "open ScanCode back"]
    );
    Ok(())
}

static NOT_ASKED: LazyLock<FakeCamera> =
    LazyLock::new(|| FakeCamera::new().access_is(Access::NotAsked, Access::Granted));
#[component]
fn NotAskedProbe() -> impl IntoElement {
    scan_probe(&NOT_ASKED)
}

#[test]
fn the_prompt_comes_only_from_a_press() -> Result<(), String> {
    let mut app = start::<NotAskedProbe>();
    app.wait_for("Allow the camera")?;
    app.wait_for("text:/Nothing it sees leaves your device/")?;
    assert_eq!(NOT_ASKED.prompts(), 0);
    assert_eq!(NOT_ASKED.running(), 0);
    app.press("Continue")?;
    app.wait_for("text:state: running back")?;
    assert_eq!(NOT_ASKED.prompts(), 1);
    Ok(())
}

static DENIED: LazyLock<FakeCamera> =
    LazyLock::new(|| FakeCamera::new().access_is(Access::Denied, Access::Denied));
#[component]
fn DeniedProbe() -> impl IntoElement {
    scan_probe(&DENIED)
}

#[test]
fn a_refusal_points_to_settings_and_never_starts() -> Result<(), String> {
    let mut app = start::<DeniedProbe>();
    app.wait_for("Camera access is off")?;
    app.wait_for("Open Settings")?;
    assert_eq!((DENIED.prompts(), DENIED.running()), (0, 0));
    Ok(())
}

static RESTRICTED: LazyLock<FakeCamera> =
    LazyLock::new(|| FakeCamera::new().access_is(Access::Restricted, Access::Restricted));
#[component]
fn RestrictedProbe() -> impl IntoElement {
    scan_probe(&RESTRICTED)
}

#[test]
fn a_restricted_camera_offers_nothing_to_press() -> Result<(), String> {
    let mut app = start::<RestrictedProbe>();
    app.wait_for("text:/parental controls/")?;
    assert!(!app.shows("Open Settings") && !app.shows("Continue"));
    assert_eq!(RESTRICTED.running(), 0);
    Ok(())
}

static NO_LENS: LazyLock<FakeCamera> = LazyLock::new(|| FakeCamera::new().lenses_are(Vec::new()));
#[component]
fn NoLensProbe() -> impl IntoElement {
    scan_probe(&NO_LENS)
}

#[test]
fn no_camera_says_so() -> Result<(), String> {
    let mut app = start::<NoLensProbe>();
    app.wait_for("No camera found")?;
    assert_eq!(NO_LENS.running(), 0);
    Ok(())
}

static IN_USE: LazyLock<FakeCamera> =
    LazyLock::new(|| FakeCamera::new().fails_to_open(Unavailable::InUse));
#[component]
fn InUseProbe() -> impl IntoElement {
    scan_probe(&IN_USE)
}

#[test]
fn a_camera_in_use_can_be_tried_again() -> Result<(), String> {
    let mut app = start::<InUseProbe>();
    app.wait_for("The camera is in use")?;
    IN_USE.opens_again();
    app.press("Try again")?;
    app.wait_for("text:state: running back")?;
    Ok(())
}

static INTERRUPTED: LazyLock<FakeCamera> = LazyLock::new(FakeCamera::new);
#[component]
fn InterruptedProbe() -> impl IntoElement {
    scan_probe(&INTERRUPTED)
}

#[test]
fn an_interruption_is_shown() -> Result<(), String> {
    let mut app = start::<InterruptedProbe>();
    app.wait_for("text:state: running back")?;
    INTERRUPTED.interrupt(&Unavailable::Interrupted);
    app.wait_for("The camera is paused")?;
    Ok(())
}

static CALL: LazyLock<FakeCamera> = LazyLock::new(FakeCamera::new);
#[component]
fn CallProbe() -> impl IntoElement {
    install(Some(Arc::new(CALL.clone())), false);
    let session = use_session(Purpose::Call, || true, |_| {});
    let shown = session.shown;
    let s2 = session.clone();
    view()
        .child(text(move || format!("state: {}", label(&shown.get()))))
        .child(button_text("Flip", move || s2.flip()))
}

#[test]
fn a_call_starts_on_the_front_lens_and_flips() -> Result<(), String> {
    let mut app = start::<CallProbe>();
    app.wait_for("text:state: running front")?;
    app.press("Flip")?;
    app.wait_for("text:state: running back")?;
    assert_eq!(CALL.log(), ["open Call front", "lens back"]);
    Ok(())
}

#[test]
fn the_front_lens_is_found_by_facing() {
    let lenses = [Lens {
        id: "w".into(),
        name: "Webcam".into(),
        facing: Facing::External,
    }];
    assert_eq!(
        Lens::preferred(&lenses, Purpose::Call).map(|l| l.id.as_str()),
        Some("w")
    );
}

static PHOTO: LazyLock<FakeCamera> = LazyLock::new(|| {
    let cam = FakeCamera::new();
    cam.photo_gives(Ok(songbird_camera::Still {
        bytes: vec![0xFF, 0xD8, 0xFF, 0xD9],
        mime: "image/jpeg",
        width: 640,
        height: 480,
    }));
    cam
});
#[component]
fn PhotoProbe() -> impl IntoElement {
    install(Some(Arc::new(PHOTO.clone())), false);
    let got = signal(String::from("none"));
    let session = use_session(Purpose::Photo, || true, |_| {});
    let shown = session.shown;
    view()
        .child(text(move || format!("state: {}", label(&shown.get()))))
        .child(text(move || format!("photo: {}", got.get())))
        .child(button_text("Shoot", move || {
            session.take_photo(move |r| {
                got.set(match r {
                    Ok(s) => format!("{}x{} {}", s.width, s.height, s.bytes.len()),
                    Err(e) => format!("{e:?}"),
                });
            });
        }))
}

#[test]
fn a_photo_comes_back_on_the_engine_thread() -> Result<(), String> {
    let mut app = start::<PhotoProbe>();
    app.wait_for("text:state: running back")?;
    app.press("Shoot")?;
    app.wait_for("text:photo: 640x480 4")?;
    assert_eq!(PHOTO.log(), ["open Photo back", "photo"]);
    Ok(())
}

static VIDEO: LazyLock<FakeCamera> = LazyLock::new(FakeCamera::new);
#[component]
fn VideoProbe() -> impl IntoElement {
    install(Some(Arc::new(VIDEO.clone())), false);
    let on = signal(false);
    let _session = use_session(Purpose::Call, move || on.get(), |_| {});
    view()
        .child(text(move || format!("video: {}", on.get())))
        .child(button_text("Toggle", move || on.update(|v| *v = !*v)))
}

#[test]
fn a_call_s_camera_follows_its_video_switch() -> Result<(), String> {
    let mut app = start::<VideoProbe>();
    app.wait_for("text:video: false")?;
    assert_eq!(VIDEO.running(), 0, "no camera before video is on");
    app.press("Toggle")?;
    app.wait_for("text:video: true")?;
    app.settle();
    assert_eq!(VIDEO.running_purposes(), vec![Purpose::Call]);
    app.press("Toggle")?;
    app.wait_for("text:video: false")?;
    app.settle();
    assert_eq!(VIDEO.running(), 0, "{:?}", VIDEO.log());
    Ok(())
}
