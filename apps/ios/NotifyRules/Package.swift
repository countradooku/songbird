// swift-tools-version:5.9
// The rules the iOS notification extension applies (Prompt 8, D-0099), as a package so they are
// unit-tested on the Mac (`swift test`) and compiled into the extension as they are.
import PackageDescription

let package = Package(
    name: "NotifyRules",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [.library(name: "NotifyRules", targets: ["NotifyRules"])],
    targets: [
        .target(name: "NotifyRules"),
        .testTarget(name: "NotifyRulesTests", dependencies: ["NotifyRules"]),
    ]
)
