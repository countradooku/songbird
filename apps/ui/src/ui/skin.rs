//! Platform skins: Songbird keeps its brand (Dusk violet, the feather,
//! the copy, the layout) and dresses its chrome in each OS's design
//! language. One [`SkinSpec`] per skin holds the shape, size, type and
//! feedback numbers; the `ui` layer and the shell read it, features never
//! do (they compose `ui::*`, which already follows it).
//!
//! | OS | Skin |
//! | --- | --- |
//! | iOS, iPadOS, Mac Catalyst, macOS | [`Skin::Apple`] (Liquid Glass, iOS 26 / macOS 26 HIG) |
//! | Android | [`Skin::Material`] (Material 3 Expressive) |
//! | Windows | [`Skin::Fluent`] (Fluent 2) |
//! | Linux | [`Skin::Adwaita`] (GNOME libadwaita) |
//! | Web and anything else | [`Skin::Material`] |
//!
//! Debug builds only: `SONGBIRD_SKIN=apple|material|fluent|adwaita`
//! overrides the OS's skin at launch, ⌘⌥S / Ctrl+Alt+S cycles it while
//! the app runs, and the gallery has a switcher.
//!
//! Builders read the spec once, while they build ([`spec`]), and keep the
//! copy in their closures: so the gallery can build one preview per skin
//! side by side ([`with_skin`]).

use std::cell::Cell;

use nsh_core::{platform::Os, prelude::*};

/// A platform design language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Skin {
    /// Apple's HIG with Liquid Glass (iOS 26, macOS 26).
    Apple,
    /// Material 3 Expressive (Android, the web).
    Material,
    /// Fluent 2 (Windows 11).
    Fluent,
    /// GNOME's libadwaita (Linux).
    Adwaita,
}

impl Skin {
    /// Every skin, in the switcher's order.
    pub const ALL: [Skin; 4] = [Skin::Apple, Skin::Material, Skin::Fluent, Skin::Adwaita];

    /// The skin an OS gets.
    pub fn for_os(os: Os) -> Skin {
        match os {
            Os::Ios | Os::MacOs => Skin::Apple,
            Os::Android => Skin::Material,
            Os::Windows => Skin::Fluent,
            Os::Linux => Skin::Adwaita,
            Os::Web => Skin::Material,
        }
    }

    /// Its lower-case name (`SONGBIRD_SKIN`, `theme.json` `skins`).
    pub fn name(self) -> &'static str {
        match self {
            Skin::Apple => "apple",
            Skin::Material => "material",
            Skin::Fluent => "fluent",
            Skin::Adwaita => "adwaita",
        }
    }

    /// Its name for people (the gallery).
    pub fn label(self) -> &'static str {
        match self {
            Skin::Apple => "Apple",
            Skin::Material => "Material",
            Skin::Fluent => "Fluent",
            Skin::Adwaita => "Adwaita",
        }
    }

    /// Parses a name, case and surrounding space ignored.
    pub fn parse(s: &str) -> Option<Skin> {
        let s = s.trim().to_ascii_lowercase();
        Skin::ALL.into_iter().find(|k| k.name() == s)
    }

    /// The next skin (the debug shortcut cycles them).
    pub fn next(self) -> Skin {
        let i = Skin::ALL.iter().position(|k| *k == self).unwrap_or(0);
        Skin::ALL[(i + 1) % Skin::ALL.len()]
    }

    /// Its numbers.
    pub fn spec(self) -> SkinSpec {
        match self {
            Skin::Apple => APPLE,
            Skin::Material => MATERIAL,
            Skin::Fluent => FLUENT,
            Skin::Adwaita => ADWAITA,
        }
    }
}

/// A radius that makes a capsule of any control (half its height or more).
pub const FULL: f32 = 999.0;

/// Corner radii, in points ([`FULL`] for a capsule).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Radii {
    /// Text fields, segmented tracks, popups and menu items.
    pub control: f32,
    /// Labelled buttons.
    pub button: f32,
    /// Icon-only buttons.
    pub icon_button: f32,
    /// Filter chips.
    pub chip: f32,
    /// Tags, tiles, inner fills.
    pub small: f32,
    /// Cards and grouped lists.
    pub card: f32,
    /// A bottom sheet's top corners.
    pub sheet: f32,
    /// A centred dialog or panel.
    pub dialog: f32,
    /// Chat bubbles.
    pub bubble: f32,
    /// A floating pane of the wide window (list, conversation, info), as
    /// the platform rounds a window-level surface (`REDESIGN.md`, Skins).
    pub pane: f32,
    /// The floating action button.
    pub fab: f32,
    /// The search field.
    pub search: f32,
}

/// Control heights for one family (small, medium, large).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Heights {
    pub sm: f32,
    pub md: f32,
    pub lg: f32,
}

/// A title's type: size (pt), weight, letter spacing (pt).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TitleType {
    pub size: f32,
    pub weight: FontWeight,
    pub tracking: f32,
}

/// What a press looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressStyle {
    /// Apple: the control dims (a highlight); buttons settle a little,
    /// list rows never scale.
    Highlight,
    /// Material: a state layer (and the ripple where NSH draws one).
    Ripple,
    /// Fluent and Adwaita: the fill shifts a step; nothing moves.
    Fill,
}

/// How surfaces stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Apple: floating chrome is Liquid Glass; content is flat.
    Glass,
    /// Material: tonal surface containers; shadow only on the FAB.
    Tonal,
    /// Fluent: layers with 1px strokes and soft shadow4/8/16.
    Shadow,
    /// Adwaita: flat; borders separate.
    Flat,
}

/// How rows in a group are separated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeparatorStyle {
    /// A hairline starting under the titles (Apple).
    Inset,
    /// Full-width 1px lines (Fluent, Adwaita boxed lists).
    Full,
    /// None: spacing and row height carry it (Material).
    None,
}

/// The phone's section navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavChrome {
    /// Apple: a floating Liquid Glass capsule inset from the edges.
    GlassCapsule,
    /// Material: an 80dp navigation bar with a 64×32 pill indicator.
    NavigationBar,
    /// Fluent: a bar of items with a 16×3 accent indicator.
    SelectorBar,
    /// Adwaita: a flat view-switcher bar.
    ViewSwitcher,
}

/// The wide window's section navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sidebar {
    /// Apple: a source list on the macOS sidebar material (vibrancy).
    SourceList,
    /// Material: an 80dp navigation rail, icon over label in a pill.
    Rail,
    /// Fluent: a NavigationView pane, a 3×16 accent pill at the item's left.
    NavigationView,
    /// Adwaita: a flat sidebar with rounded selection.
    Flat,
}

/// Where a header's title sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleAlign {
    /// At the leading edge.
    Leading,
    /// Centred on phone-like widths, leading on wide ones.
    CenteredNarrow,
    /// Always centred (a header bar).
    Centered,
}

/// When a section's root shows a large title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargeTitle {
    Never,
    /// On phone-like widths only.
    Phone,
    /// Everywhere.
    Always,
}

/// The switch's geometry, in points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SwitchSpec {
    pub track_w: f32,
    pub track_h: f32,
    /// The track's border.
    pub border: f32,
    /// The thumb's side when off and when on (Material's grows).
    pub thumb_off: f32,
    pub thumb_on: f32,
    /// The gap from the track's outer edge to the thumb, off and on.
    pub inset_off: f32,
    pub inset_on: f32,
    /// The off thumb is the ink colour (Fluent, Material), not the knob.
    pub ink_thumb_off: bool,
    /// The off track is filled with the strong `input` colour (Adwaita).
    pub filled_off: bool,
}

impl SwitchSpec {
    /// How far the thumb moves from its off place to its on place.
    pub fn travel(&self) -> f32 {
        (self.track_w - self.inset_on - self.thumb_on) - self.inset_off
    }
}

/// Everything a skin sets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SkinSpec {
    pub skin: Skin,
    pub radius: Radii,
    /// Button heights on desktops and on phones.
    pub desktop: Heights,
    pub mobile: Heights,
    /// Text field height, desktops and phones.
    pub field_h: (f32, f32),
    /// Pushed pages' titles and wide-window section titles.
    pub page_title: TitleType,
    /// Section roots' large titles.
    pub large_title: TitleType,
    pub large_title_on: LargeTitle,
    pub title_align: TitleAlign,
    /// The header bar's height.
    pub header_h: f32,
    /// Section titles over groups: uppercase (Apple), in primary (Material).
    pub section_upper: bool,
    pub section_primary: bool,
    pub press: PressStyle,
    pub elevation: Elevation,
    pub separator: SeparatorStyle,
    /// Groups and cards carry a 1px border.
    pub card_stroke: bool,
    pub nav: NavChrome,
    pub sidebar: Sidebar,
    /// The sidebar's width on wide windows.
    pub sidebar_w: f32,
    pub switch: SwitchSpec,
    /// The platform has a floating action button (else the action goes
    /// in the header).
    pub fab: bool,
    /// Primary buttons are pills while other buttons are not (Adwaita's
    /// "suggested action" pill).
    pub pill_primary: bool,
    /// Sheets are centred dialogs at every width (Fluent).
    pub dialogs_centred: bool,
    /// The back control is an arrow (Material, Fluent) or a chevron.
    pub back_arrow: bool,
}

const fn tt(size: f32, weight: u16, tracking: f32) -> TitleType {
    TitleType { size, weight: FontWeight(weight), tracking }
}

/// Apple, Liquid Glass (iOS 26 / macOS 26 HIG).
pub const APPLE: SkinSpec = SkinSpec {
    skin: Skin::Apple,
    radius: Radii {
        control: 10.0,
        button: FULL,
        icon_button: FULL,
        chip: FULL,
        small: 7.0,
        card: 18.0,
        sheet: 28.0,
        dialog: 24.0,
        bubble: 18.0,
        pane: 16.0,
        fab: FULL,
        search: FULL,
    },
    desktop: Heights { sm: 24.0, md: 30.0, lg: 38.0 },
    mobile: Heights { sm: 36.0, md: 48.0, lg: 54.0 },
    field_h: (32.0, 48.0),
    page_title: tt(17.0, 600, -0.4),
    large_title: tt(34.0, 700, 0.4),
    large_title_on: LargeTitle::Phone,
    title_align: TitleAlign::CenteredNarrow,
    header_h: 52.0,
    section_upper: true,
    section_primary: false,
    press: PressStyle::Highlight,
    elevation: Elevation::Glass,
    separator: SeparatorStyle::Inset,
    card_stroke: false,
    nav: NavChrome::GlassCapsule,
    sidebar: Sidebar::SourceList,
    sidebar_w: 208.0,
    switch: SwitchSpec {
        track_w: 51.0,
        track_h: 31.0,
        border: 1.0,
        thumb_off: 27.0,
        thumb_on: 27.0,
        inset_off: 2.0,
        inset_on: 2.0,
        ink_thumb_off: false,
        filled_off: false,
    },
    fab: false,
    pill_primary: false,
    dialogs_centred: false,
    back_arrow: false,
};

/// Material 3 Expressive.
pub const MATERIAL: SkinSpec = SkinSpec {
    skin: Skin::Material,
    radius: Radii {
        control: 4.0,
        button: FULL,
        icon_button: FULL,
        chip: 8.0,
        small: 8.0,
        card: 20.0,
        sheet: 28.0,
        dialog: 28.0,
        bubble: 20.0,
        pane: 24.0,
        fab: 16.0,
        search: FULL,
    },
    desktop: Heights { sm: 32.0, md: 40.0, lg: 48.0 },
    mobile: Heights { sm: 40.0, md: 48.0, lg: 56.0 },
    field_h: (40.0, 56.0),
    page_title: tt(22.0, 400, 0.0),
    large_title: tt(32.0, 500, 0.0),
    large_title_on: LargeTitle::Phone,
    title_align: TitleAlign::Leading,
    header_h: 64.0,
    section_upper: false,
    section_primary: true,
    press: PressStyle::Ripple,
    elevation: Elevation::Tonal,
    separator: SeparatorStyle::None,
    card_stroke: false,
    nav: NavChrome::NavigationBar,
    sidebar: Sidebar::Rail,
    sidebar_w: 88.0,
    switch: SwitchSpec {
        track_w: 52.0,
        track_h: 32.0,
        border: 2.0,
        thumb_off: 16.0,
        thumb_on: 24.0,
        inset_off: 8.0,
        inset_on: 4.0,
        ink_thumb_off: true,
        filled_off: false,
    },
    fab: true,
    pill_primary: false,
    dialogs_centred: false,
    back_arrow: true,
};

/// Fluent 2 (Windows 11).
pub const FLUENT: SkinSpec = SkinSpec {
    skin: Skin::Fluent,
    radius: Radii {
        control: 4.0,
        button: 4.0,
        icon_button: 4.0,
        chip: 4.0,
        small: 4.0,
        card: 8.0,
        sheet: 8.0,
        dialog: 8.0,
        bubble: 8.0,
        pane: 8.0,
        fab: 4.0,
        search: 4.0,
    },
    desktop: Heights { sm: 24.0, md: 32.0, lg: 40.0 },
    mobile: Heights { sm: 32.0, md: 40.0, lg: 48.0 },
    field_h: (32.0, 40.0),
    page_title: tt(20.0, 600, 0.0),
    large_title: tt(28.0, 600, 0.0),
    large_title_on: LargeTitle::Always,
    title_align: TitleAlign::Leading,
    header_h: 48.0,
    section_upper: false,
    section_primary: false,
    press: PressStyle::Fill,
    elevation: Elevation::Shadow,
    separator: SeparatorStyle::Full,
    card_stroke: true,
    nav: NavChrome::SelectorBar,
    sidebar: Sidebar::NavigationView,
    sidebar_w: 200.0,
    switch: SwitchSpec {
        track_w: 40.0,
        track_h: 20.0,
        border: 1.0,
        thumb_off: 12.0,
        thumb_on: 12.0,
        inset_off: 4.0,
        inset_on: 4.0,
        ink_thumb_off: true,
        filled_off: false,
    },
    fab: false,
    pill_primary: false,
    dialogs_centred: true,
    back_arrow: true,
};

/// GNOME libadwaita.
pub const ADWAITA: SkinSpec = SkinSpec {
    skin: Skin::Adwaita,
    radius: Radii {
        control: 6.0,
        button: 6.0,
        icon_button: 6.0,
        chip: FULL,
        small: 6.0,
        card: 12.0,
        sheet: 14.0,
        dialog: 14.0,
        bubble: 14.0,
        pane: 12.0,
        fab: 6.0,
        search: 6.0,
    },
    desktop: Heights { sm: 24.0, md: 34.0, lg: 42.0 },
    mobile: Heights { sm: 34.0, md: 42.0, lg: 50.0 },
    field_h: (34.0, 42.0),
    page_title: tt(15.0, 700, 0.0),
    large_title: tt(15.0, 700, 0.0),
    large_title_on: LargeTitle::Never,
    title_align: TitleAlign::Centered,
    header_h: 47.0,
    section_upper: false,
    section_primary: false,
    press: PressStyle::Fill,
    elevation: Elevation::Flat,
    separator: SeparatorStyle::Full,
    card_stroke: true,
    nav: NavChrome::ViewSwitcher,
    sidebar: Sidebar::Flat,
    sidebar_w: 200.0,
    switch: SwitchSpec {
        track_w: 46.0,
        track_h: 26.0,
        border: 0.0,
        thumb_off: 20.0,
        thumb_on: 20.0,
        inset_off: 3.0,
        inset_on: 3.0,
        ink_thumb_off: false,
        filled_off: true,
    },
    fab: false,
    pill_primary: true,
    dialogs_centred: false,
    back_arrow: false,
};

impl SkinSpec {
    /// Button heights for the current family.
    pub fn heights(&self) -> Heights {
        if is_desktop() { self.desktop } else { self.mobile }
    }

    /// How much of a phone window's bottom (above the safe area) the
    /// section bar takes, its floating gap included.
    pub fn tab_bar_h(&self) -> f32 {
        match self.nav {
            NavChrome::GlassCapsule => 70.0,
            NavChrome::NavigationBar => 80.0,
            NavChrome::SelectorBar => 69.0,
            NavChrome::ViewSwitcher => 63.0,
        }
    }

    /// The icon for "new chat" in a header: Apple's square and pencil,
    /// a pencil elsewhere.
    pub fn compose_icon(&self) -> super::icons::Icon {
        if self.skin == Skin::Apple { super::icons::Icon::Compose } else { super::icons::Icon::Edit }
    }

    /// A section root shows a large title at this width.
    pub fn large_title_now(&self, wide: bool) -> bool {
        match self.large_title_on {
            LargeTitle::Never => false,
            LargeTitle::Phone => !wide,
            LargeTitle::Always => true,
        }
    }

    /// The header title is centred at this width.
    pub fn centred_now(&self, wide: bool) -> bool {
        match self.title_align {
            TitleAlign::Leading => false,
            TitleAlign::CenteredNarrow => !wide,
            TitleAlign::Centered => true,
        }
    }
}

// ---------------------------------------------------------------- choice

thread_local! {
    /// A skin for what is being built now ([`with_skin`]).
    static SCOPED: Cell<Option<Skin>> = const { Cell::new(None) };
}

/// The skin chosen while the app runs (debug: the gallery switcher and
/// the shortcut); `None` follows the OS (and `SONGBIRD_SKIN`).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct ActiveSkin(pub Option<Skin>);

/// `SONGBIRD_SKIN`, read once (debug builds only).
fn env_skin() -> Option<Skin> {
    if !cfg!(debug_assertions) {
        return None;
    }
    static ENV: std::sync::OnceLock<Option<Skin>> = std::sync::OnceLock::new();
    *ENV.get_or_init(|| std::env::var("SONGBIRD_SKIN").ok().and_then(|v| Skin::parse(&v)))
}

/// The skin of this OS (and, in debug builds, `SONGBIRD_SKIN`), ignoring
/// any run-time choice.
pub fn platform_skin() -> Skin {
    env_skin().unwrap_or_else(|| Skin::for_os(try_os().unwrap_or_default()))
}

/// The skin to draw with now: a scoped preview's, else the run-time
/// choice (debug), else [`platform_skin`]. Does not subscribe.
pub fn skin() -> Skin {
    if let Some(s) = SCOPED.with(Cell::get) {
        return s;
    }
    if cfg!(debug_assertions)
        && try_os().is_some()
        && let Some(s) = global::<ActiveSkin>().with_untracked(|a| a.0)
    {
        return s;
    }
    platform_skin()
}

/// [`skin`]'s numbers.
pub fn spec() -> SkinSpec {
    skin().spec()
}

/// The skin, subscribing to the run-time choice: what the shell and the
/// theme rebuild on.
pub fn tracked_skin() -> Skin {
    if cfg!(debug_assertions) {
        global::<ActiveSkin>().with(|a| a.0).unwrap_or_else(platform_skin)
    } else {
        platform_skin()
    }
}

/// Changes the app's skin while it runs (debug builds; release builds
/// always follow the OS).
pub fn set_skin(skin: Skin) {
    if cfg!(debug_assertions) {
        global::<ActiveSkin>().set(ActiveSkin(Some(skin)));
    }
}

/// Builds `f` as if the app had `skin` (the gallery's side-by-side
/// previews): builders read the spec while they build.
pub fn with_skin<R>(skin: Skin, f: impl FnOnce() -> R) -> R {
    let before = SCOPED.with(|c| c.replace(Some(skin)));
    let out = f();
    SCOPED.with(|c| c.set(before));
    out
}

/// Debug builds on desktops: ⌘⌥S / Ctrl+Alt+S moves to the next skin.
pub fn install_debug_shortcut() {
    if cfg!(debug_assertions) && is_desktop() {
        on_key("mod+alt+s", |_| {
            let next = skin().next();
            set_skin(next);
            super::controls::toast(format!("Skin: {}", next.label()));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_os_gets_its_skin() {
        assert_eq!(Skin::for_os(Os::Ios), Skin::Apple);
        assert_eq!(Skin::for_os(Os::MacOs), Skin::Apple);
        assert_eq!(Skin::for_os(Os::Android), Skin::Material);
        assert_eq!(Skin::for_os(Os::Windows), Skin::Fluent);
        assert_eq!(Skin::for_os(Os::Linux), Skin::Adwaita);
        assert_eq!(Skin::for_os(Os::Web), Skin::Material);
    }

    #[test]
    fn names_round_trip_and_cycle() {
        for s in Skin::ALL {
            assert_eq!(Skin::parse(s.name()), Some(s));
            assert_eq!(Skin::parse(&format!(" {} ", s.label().to_uppercase())), Some(s));
            assert_eq!(s.spec().skin, s);
        }
        assert_eq!(Skin::parse("cupertino"), None);
        let mut s = Skin::Apple;
        for _ in 0..4 {
            s = s.next();
        }
        assert_eq!(s, Skin::Apple);
    }

    #[test]
    fn scoped_skin_wins_and_restores() {
        let outside = skin();
        let inner = with_skin(Skin::Fluent, || (skin(), with_skin(Skin::Adwaita, skin), skin()));
        assert_eq!(inner, (Skin::Fluent, Skin::Adwaita, Skin::Fluent));
        assert_eq!(skin(), outside);
    }

    #[test]
    fn apple_follows_the_hig() {
        let a = APPLE;
        assert_eq!((a.switch.track_w, a.switch.track_h), (51.0, 31.0));
        assert_eq!(a.large_title.size, 34.0);
        assert_eq!(a.large_title.weight, FontWeight(700));
        assert_eq!(a.radius.button, FULL, "controls are capsules");
        assert!(a.radius.sheet >= 20.0);
        assert!(!a.fab, "iOS has no floating action button");
        assert_eq!(a.press, PressStyle::Highlight);
        assert_eq!(a.nav, NavChrome::GlassCapsule);
        assert_eq!(a.separator, SeparatorStyle::Inset);
    }

    #[test]
    fn material_is_m3_expressive() {
        let m = MATERIAL;
        assert_eq!((m.switch.track_w, m.switch.track_h), (52.0, 32.0));
        assert!(m.switch.thumb_on > m.switch.thumb_off, "the thumb grows when on");
        assert_eq!(m.radius.fab, 16.0);
        assert_eq!(m.radius.sheet, 28.0);
        assert_eq!(m.radius.button, FULL);
        assert!((16.0..=28.0).contains(&m.radius.card));
        assert_eq!(m.mobile.md, 48.0);
        assert!(m.fab);
        assert_eq!(m.press, PressStyle::Ripple);
        assert_eq!(m.nav, NavChrome::NavigationBar);
    }

    #[test]
    fn fluent_is_fluent_2() {
        let f = FLUENT;
        assert_eq!((f.switch.track_w, f.switch.track_h), (40.0, 20.0));
        assert_eq!((f.radius.control, f.radius.button, f.radius.card, f.radius.dialog), (4.0, 4.0, 8.0, 8.0));
        assert_eq!((f.large_title.size, f.page_title.size), (28.0, 20.0));
        assert_eq!(f.large_title.weight, FontWeight(600));
        assert!(f.card_stroke && !f.fab && f.dialogs_centred);
        assert_eq!(f.press, PressStyle::Fill);
        assert_eq!(f.sidebar, Sidebar::NavigationView);
    }

    #[test]
    fn adwaita_is_libadwaita() {
        let g = ADWAITA;
        assert!((46.0..=47.0).contains(&g.header_h));
        assert_eq!(g.title_align, TitleAlign::Centered);
        assert_eq!((g.radius.button, g.radius.card), (6.0, 12.0));
        assert!((12.0..=16.0).contains(&g.radius.dialog));
        assert!(g.pill_primary && g.card_stroke && !g.fab);
        assert_eq!(g.elevation, Elevation::Flat);
    }

    #[test]
    fn every_switch_thumb_fits_its_track() {
        for s in Skin::ALL {
            let w = s.spec().switch;
            assert!(w.thumb_off + 2.0 * w.border <= w.track_h, "{s:?} off thumb");
            assert!(w.thumb_on <= w.track_h, "{s:?} on thumb");
            assert!(w.travel() > 0.0, "{s:?} travel");
            assert!(w.inset_off + w.thumb_off + w.inset_on <= w.track_w, "{s:?} off fits");
            assert!(w.travel() >= w.thumb_off * 0.6, "{s:?} the move reads");
        }
    }

    /// `REDESIGN.md`, Skins: the floating panes' corners.
    #[test]
    fn panes_round_as_each_platform_does() {
        let r = |s: Skin| s.spec().radius.pane;
        assert_eq!(
            (r(Skin::Apple), r(Skin::Material), r(Skin::Fluent), r(Skin::Adwaita)),
            (16.0, 24.0, 8.0, 12.0)
        );
    }

    #[test]
    fn touch_targets_hold_on_phones() {
        for s in Skin::ALL {
            let sp = s.spec();
            assert!(sp.mobile.md >= 40.0, "{s:?}");
            assert!(sp.field_h.1 >= 40.0, "{s:?}");
            assert!(sp.header_h >= 44.0, "{s:?}");
        }
    }
}
