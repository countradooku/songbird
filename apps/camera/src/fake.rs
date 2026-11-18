//! A scripted camera for headless tests: what access is and what the prompt answers, which
//! lenses exist, whether starting fails, and what the camera "sees" (codes, frames, an
//! interruption). It records starts, stops and prompts, so tests prove the camera runs only
//! while it should.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::{
    Access, AccessCallback, Backend, Capture, CaptureError, Config, Facing, Frame, Lens, Sink,
    Still, StillCallback, Unavailable,
};

#[derive(Default)]
struct State {
    access: Option<Access>,
    answer: Option<Access>,
    prompts: u32,
    lenses: Vec<Lens>,
    fail_open: Option<Unavailable>,
    live: Vec<(u64, Sink, Config)>,
    next_id: u64,
    log: Vec<String>,
    photo: Option<Result<Still, CaptureError>>,
}

/// The fake camera; clones share one state.
#[derive(Clone)]
pub struct FakeCamera(Arc<Mutex<State>>);

impl Default for FakeCamera {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeCamera {
    /// Access granted, a back and a front lens, starting works.
    #[must_use]
    pub fn new() -> Self {
        let state = State {
            access: Some(Access::Granted),
            answer: Some(Access::Granted),
            lenses: vec![
                Lens {
                    id: "back".into(),
                    name: "Back Camera".into(),
                    facing: Facing::Back,
                },
                Lens {
                    id: "front".into(),
                    name: "Front Camera".into(),
                    facing: Facing::Front,
                },
            ],
            next_id: 1,
            ..State::default()
        };
        FakeCamera(Arc::new(Mutex::new(state)))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Access is `now`; the prompt answers `answer`.
    #[must_use]
    pub fn access_is(self, now: Access, answer: Access) -> Self {
        {
            let mut s = self.lock();
            s.access = Some(now);
            s.answer = Some(answer);
        }
        self
    }

    /// The device has these lenses.
    #[must_use]
    pub fn lenses_are(self, lenses: Vec<Lens>) -> Self {
        self.lock().lenses = lenses;
        self
    }

    /// Starting fails with `why`.
    #[must_use]
    pub fn fails_to_open(self, why: Unavailable) -> Self {
        self.lock().fail_open = Some(why);
        self
    }

    /// Starting works again (after [`Self::fails_to_open`]).
    pub fn opens_again(&self) {
        self.lock().fail_open = None;
    }

    /// A photo taken now gives `result`.
    pub fn photo_gives(&self, result: Result<Still, CaptureError>) {
        self.lock().photo = Some(result);
    }

    /// Every running capture sees a code with `text`.
    pub fn show_code(&self, text: &str) {
        for (_, sink, _) in &self.lock().live {
            sink.code(text);
        }
    }

    /// Every running capture hands the app `frame`.
    pub fn show_frame(&self, frame: &Frame) {
        for (_, sink, _) in &self.lock().live {
            sink.frame(frame.clone());
        }
    }

    /// The system takes the camera away from every running capture.
    pub fn interrupt(&self, why: &Unavailable) {
        for (_, sink, _) in &self.lock().live {
            sink.unavailable(why.clone());
        }
    }

    /// How many captures are running.
    #[must_use]
    pub fn running(&self) -> usize {
        self.lock().live.len()
    }

    /// The purposes of the running captures.
    #[must_use]
    pub fn running_purposes(&self) -> Vec<crate::Purpose> {
        self.lock().live.iter().map(|(_, _, c)| c.purpose).collect()
    }

    /// How many times the system prompt was shown.
    #[must_use]
    pub fn prompts(&self) -> u32 {
        self.lock().prompts
    }

    /// What happened, in order: `open <purpose> <lens>`, `stop`, `lens <id>`, `torch on|off`,
    /// `photo`.
    #[must_use]
    pub fn log(&self) -> Vec<String> {
        self.lock().log.clone()
    }
}

impl Backend for FakeCamera {
    fn access(&self) -> Access {
        self.lock().access.unwrap_or(Access::NotAsked)
    }

    fn request_access(&self, done: AccessCallback) {
        let answer = {
            let mut s = self.lock();
            s.prompts += 1;
            let answer = s.answer.unwrap_or(Access::Denied);
            s.access = Some(answer);
            answer
        };
        done(answer);
    }

    fn lenses(&self) -> Vec<Lens> {
        self.lock().lenses.clone()
    }

    fn open(&self, config: Config, sink: Sink) -> Result<Box<dyn Capture>, Unavailable> {
        let mut s = self.lock();
        if s.access != Some(Access::Granted) {
            return Err(Unavailable::Failed("no access".into()));
        }
        if let Some(why) = s.fail_open.clone() {
            return Err(why);
        }
        if !s.lenses.iter().any(|l| l.id == config.lens) {
            return Err(Unavailable::NoCamera);
        }
        let id = s.next_id;
        s.next_id += 1;
        s.log
            .push(format!("open {:?} {}", config.purpose, config.lens));
        sink.running(&config.lens);
        s.live.push((id, sink, config));
        Ok(Box::new(FakeCapture {
            camera: self.clone(),
            id,
        }))
    }

    fn settings_url(&self) -> Option<&'static str> {
        Some("app-settings:")
    }
}

struct FakeCapture {
    camera: FakeCamera,
    id: u64,
}

impl Capture for FakeCapture {
    fn set_lens(&mut self, lens: &str) {
        let mut s = self.camera.lock();
        s.log.push(format!("lens {lens}"));
        if let Some((_, sink, config)) = s.live.iter_mut().find(|(id, _, _)| *id == self.id) {
            lens.clone_into(&mut config.lens);
            sink.running(lens);
        }
    }

    fn set_torch(&mut self, on: bool) -> bool {
        self.camera
            .lock()
            .log
            .push(format!("torch {}", if on { "on" } else { "off" }));
        true
    }

    fn capture_photo(&mut self, done: StillCallback) {
        let result = {
            let mut s = self.camera.lock();
            s.log.push("photo".into());
            let purpose = s
                .live
                .iter()
                .find(|(id, _, _)| *id == self.id)
                .map(|(_, _, c)| c.purpose);
            if purpose == Some(crate::Purpose::Photo) {
                s.photo
                    .clone()
                    .unwrap_or(Err(CaptureError::Failed("no photo scripted".into())))
            } else {
                Err(CaptureError::WrongPurpose)
            }
        };
        done(result);
    }

    fn preview_id(&self) -> u64 {
        self.id
    }
}

impl Drop for FakeCapture {
    fn drop(&mut self) {
        let mut s = self.camera.lock();
        s.live.retain(|(id, _, _)| *id != self.id);
        s.log.push("stop".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Purpose};

    #[test]
    fn a_capture_runs_until_dropped_and_sees_what_is_shown() {
        let cam = FakeCamera::new();
        let (sink, events, _) = Sink::new();
        let capture = cam
            .open(
                Config {
                    purpose: Purpose::ScanCode,
                    lens: "back".into(),
                },
                sink,
            )
            .unwrap();
        cam.show_code("hello");
        assert_eq!(cam.running(), 1);
        drop(capture);
        assert_eq!(cam.running(), 0);
        cam.show_code("unseen");
        assert_eq!(
            events.drain(),
            vec![
                Event::Running {
                    lens: "back".into()
                },
                Event::Code("hello".into())
            ]
        );
        assert_eq!(cam.log(), vec!["open ScanCode back", "stop"]);
    }

    #[test]
    fn without_access_nothing_starts() {
        let cam = FakeCamera::new().access_is(Access::NotAsked, Access::Denied);
        let (sink, _, _) = Sink::new();
        assert!(
            cam.open(
                Config {
                    purpose: Purpose::Photo,
                    lens: "back".into()
                },
                sink
            )
            .is_err()
        );
        let got = Arc::new(Mutex::new(None));
        let g = got.clone();
        cam.request_access(Box::new(move |a| *g.lock().unwrap() = Some(a)));
        assert_eq!(*got.lock().unwrap(), Some(Access::Denied));
        assert_eq!(cam.prompts(), 1);
    }
}
