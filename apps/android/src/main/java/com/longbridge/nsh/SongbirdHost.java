package com.longbridge.nsh;

import android.app.Activity;
import android.os.Bundle;

/**
 * What Songbird's own activity needs of NSH that NSH keeps to its package: the standalone
 * app's limits and window setup, exactly as {@link AppActivity} uses them (D-0113). Songbird
 * compiles NSH's Java sources with its host, so this sits in their package.
 */
public final class SongbirdHost {
    private SongbirdHost() {}

    /** As {@code AppActivity}: an app on its own, not a module embedded in another app. */
    public static void standalone(NshView view) {
        view.useStandaloneLimits();
    }

    /** Draw behind the system bars, with icons following light and dark mode. */
    public static void edgeToEdge(Activity activity) {
        DevActivity.edgeToEdge(activity);
    }

    /** The system bars' icons after a configuration change. */
    public static void systemBars(Activity activity) {
        DevActivity.systemBars(activity);
    }

    /** Development builds only: the environment `nsh run` passes. */
    public static void applyEnv(Bundle extras) {
        DevActivity.applyEnv(extras);
    }
}
