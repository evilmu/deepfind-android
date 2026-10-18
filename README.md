# DeepFind

**Android Forensic Intelligence — Discover. Analyze. Reveal.**

Open-source Android artifact discovery and binary inspection. First alpha uses the Android Storage Access Framework (SAF) to scan user-selected folders **read-only**, recognize file signatures, inspect headers and export reports. Android private app caches and root examination are **not** included in this alpha.

**Status:** v0.1.0-alpha; build and tests via GitHub Actions. A successful Android CI run publishes an installable debug APK as a workflow artifact.

## Development

Android Studio, Java 17, Android SDK 35; Gradle 8.9.

```sh
gradle :core:signatures:test :app:assembleDebug
```

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## License

GPL-3.0-only. See [LICENSE](LICENSE) and [implementation_plan.md](implementation_plan.md).
