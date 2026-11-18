// Songbird's Android host (D-0110, D-0113): the NSH app plus what a packaged NSH app cannot
// have (the camera's native component and its permission). FCM, UnifiedPush and
// ConnectionService join later (D-0099).
pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "songbird"
