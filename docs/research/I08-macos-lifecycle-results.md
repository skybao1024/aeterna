# I08 macOS lifecycle and activity results

## Status

**In progress, not accepted.** The user stopped the original checkpoint on
2026-09-27 and resumed I08 on 2026-09-28 against the accepted I09-I14 client
baseline. Repository implementation was approved on 2026-09-22. The integrated
revision passes the canonical automated checks and a signed current-host
activity-agent launch. The exact Argon2 replay passed its time and benchmark
process memory targets on the current host and a distinct Apple Silicon
macOS 15.5 MacBook Pro. Signed standard-path launch, Login Item registration
with rollback, vault save/discard, and screen-lock behavior have been observed
on the MacBook. A MacBook sleep/wake attempt locked the vault, discarded the
unsaved edit, and restored the original power setting; other native lifecycle
cases remain required. A warmed current-host energy measurement and Instruments
trace found approximately 27 named-agent wakeups/minute. On 2026-09-28 the owner
approved changing the limit to 30/minute while retaining every five-second
gate read; a full-length named-thread measurement against that revised limit
remains required. The exact synthetic Keychain gate was deleted and
independently verified absent on both hosts at the recorded checkpoint;
subsequent app launches require another final cleanup check.
No native result from the old checkpoint is acceptance evidence for the
integrated revision.

## 2026-09-28 reconciliation and read-only preflight

- Clean client `main` at `0da6166` was the resumed baseline. The preserved
  `090912f` I08 checkpoint was merged file by file; only the development plan,
  Rust app setup, React app shell, and two locale resources had textual
  conflicts. Those were resolved to retain I09-I14 protocol, recovery, UI,
  and vault behavior. The plan remains at **In progress**.
- The idle worker had a 100 ms fixed sleep, implying about 600 idle wakeups
  per minute before the required 5-second samples. It now waits on the bounded
  native event receiver until the next sample deadline, so the repository
  implementation no longer has that known energy-budget violation. Native
  15-minute CPU/wakeup/RSS measurement is still required.
- Startup leaves activity non-ready until an accessible gate sample is
  observed. Corrupt local health, shutdown, queue disconnect, or failure to
  lock the vault now keep the agent fail-closed; a failed vault lock requests
  nonzero process exit, including during controlled shutdown. Lifecycle state
  and IPC handlers are registered only on macOS, leaving the Windows vault
  path without an I08 health-file write.
  The frontend retries locale synchronization after a hidden login-item launch
  becomes focused. The `engineering-tools` binary `i08_memory_pressure`
  provides a bounded, touched 512 MiB allocation for the exact KDF replay.
- The feature-gated exact-delete probe now reports only a numeric
  Security.framework status if its already validated exact delete query fails.
  This permits diagnosis of the earlier generic `gate_native_failure` without
  printing any Keychain value, item attributes, or access group. The fixed
  probe later deleted the exact synthetic gate on both native hosts, as
  recorded below.
- Final integrated `npm run check` passed after the shutdown fix with bundled Node 24.19.0 and Rust
  1.98.1: 26 frontend tests, protocol fixture/package checks, production web
  build and asset scan, all-target/all-feature Clippy, 130 Rust library tests,
  two probe-parser tests, 15 vault integration tests, and all-target/all-feature
  `cargo check`. The I07 one-GiB fixture remains intentionally ignored here
  after its earlier independent acceptance run. The repository pins Node
  24.21.0 and npm 11.19.0; this host provided Node 24.19.0 and npm 10.9.2, so
  exact frontend toolchain equivalence remains unverified.
- Final `npm run desktop:build` passed after the shutdown fix. Its
  distribution-unsigned arm64 Mach-O
  executable has a macOS 15.0 load-command minimum and SHA-256
  `5f000f93ab4baa6c29d5406768c2c815b01eff530122e3cf4ec7746658e3bc21`.
  It links AppKit, CoreGraphics, Security, ServiceManagement,
  UserNotifications, and WebKit. It has an ad-hoc linker signature and no Team
  identifier, so it is not native signing or acceptance evidence. The pinned
  toolchain again emitted the nonfatal `rust-objcopy` missing-`libLLVM.dylib`
  warning; debug stripping remains unverified for a distributable build.
- Read-only host-context signing preflight found one available Apple Development
  identity. The existing signing fixture points to the unexpired profile and
  an entitlement file whose app identifier and Team match that profile. The
  profile permits the development Keychain group through its wildcard, while
  the entitlement requests only the exact app group. No certificate, profile,
  or signing state was changed by this preflight.
- Current host: Apple Silicon arm64, macOS 26.3 build 25D125. Host-context
  read-only inspection of the preserved signed candidate confirmed bundle ID
  `dev.aeterna.desktop.foundation`, a macOS 15.0 minimum, only
  `aeterna-desktop` in `Contents/MacOS`, and strict signature verification.
  Its embedded development profile expires on 2026-09-29T09:52:27Z and was
  unexpired at preflight. Its fixed read-only probe returned
  `gate_metadata_valid=true`; the exact synthetic gate therefore remains.
  The process inventory found no running Aeterna executable. The candidate's
  executable hash remains
  `6a174c47e437d832a975e78bbe4adad19fa7445b7196dbd98529dfd39662c400`.
  None of those checks changed Keychain, Login Items, notifications, profile,
  system clock, or process state. A new signed candidate is required for the
  integrated revision before native startup or matrix testing.
- The sandboxed profile decode and signature checks could not establish host
  trust; the same read-only operations succeeded in host context. No Keychain
  value or access group was printed.
- With explicit approval on 2026-09-28, the integrated source was built as a
  feature-gated signed I08 test bundle at
  `src-tauri/target/release/bundle/macos/Aeterna.app`. The build passed and
  emitted only the known nonfatal `rust-objcopy` debug-strip warning. The
  executable is arm64, has a macOS 15.0 Mach-O minimum, and has SHA-256
  `cd79d834414f267e25435494ca53cc112c1ac019ea8ebf9082de3f78760f2dba`.
  It is the only executable in `Contents/MacOS`. Host-context
  `codesign --verify --deep --strict` passed; the hardened-runtime Team,
  application identifier, exact Keychain group, and embedded profile match.
  The profile expires on 2026-09-29T09:52:27Z. The signed executable's fixed
  read-only `--i08-gate-probe metadata` action returned
  `gate_metadata_valid=true`. The candidate has not been launched. Signing
  and this probe did not change the Keychain gate, Login Items, notifications,
  or the application-support health record. An ordinary `npm run desktop:build`
  then restored the probe-free unsigned release executable with its prior
  SHA-256 `5f000f93ab4baa6c29d5406768c2c815b01eff530122e3cf4ec7746658e3bc21`;
  the signed test bundle's executable hash remained unchanged.

## 2026-09-28 integrated native validation

- The first signed integrated candidate launched as PID 49221 from its exact
  release bundle, but its UI reported `agent_error` and no application-support
  health record existed. A display-name UI lookup also launched an unrelated
  old debug bundle as PID 49345; that process was identified by its exact
  executable path and terminated. PID 49221 then exited through the signed
  app's normal Quit action. No Login Item or notification state was changed.
- The clean first-run failure was traced to the health store trying to create
  `health` before its application-data parent existed. A focused regression
  test failed with `HealthError::Io` before the fix and passed afterward. The
  macOS health store now creates and opens the app and health directories
  relative to retained parent descriptors, rejects symlink substitution, and
  validates ownership and private modes. It syncs newly created parent
  directory entries before persisting the record. A separate app-directory symlink
  regression passed. The final integrated `npm run check` passed with 26
  frontend tests, 132 passing Rust library tests, one intentional one-GiB
  ignore, two probe-parser tests, and 15 vault integration tests.
- The repaired integrated candidate was signed with the same unexpired
  development identity and profile. Host-context strict signature verification
  passed. Its only arm64 executable has SHA-256
  `43d941eb6c8cf111e3bf10a8b85f6c8208b8de99d9859b0ef160590781e58e65`.
  It launched as PID 51773 from the exact signed bundle. The visible UI
  reported `Activity agent ready`, `Login Item unavailable`, and
  `Notifications not requested`. The application-data directory and health
  directory were mode 0700; the 96-byte health record was mode 0600. The same
  signed bundle's fixed read-only probe returned `gate_metadata_valid=true`.
  No permission prompt appeared, and the exact synthetic gate was unchanged.
- Through the user-provided UU remote session, a distinct MacBook Pro reported
  arm64, Darwin 24.5.0, and macOS 15.5. Its existing SSH service is reachable
  from the current Mac, but no passwordless authentication was configured.
  UU remote reported that its file-transfer feature is not yet available. AirDrop
  was subsequently used to transfer the signed test bundle; the attempt and
  failure are recorded below.
  The current development profile lists one device, and a read-only
  provisioning-UDID comparison confirmed that device is the current Mac mini.
  The MacBook needs a device-inclusive profile and an appropriately signed
  candidate before its native result can qualify; no device identifier was
  added to the result ledger.
- The exact pinned Node 24.21.0 and npm 11.19.0 were subsequently found in the
  host's existing Homebrew installation. With that Node and pinned Rust
  1.98.1, the full `npm run check` passed after the first-run durability fix:
  26 frontend tests, 132 passing Rust library tests, one intentional one-GiB
  ignore, two main-binary tests, 15 vault integration tests, formatting,
  Clippy, type checking, protocol checks, and production web build. The
  ordinary `npm run desktop:build` also passed. Both release builds still
  emitted the nonfatal `rust-objcopy` missing-`libLLVM.dylib` warning, so debug
  stripping is not verified.
- The signed final-source I08 candidate passed host-context
  `codesign --verify --deep --strict`; its sole arm64 executable has SHA-256
  `f9bc792c8c074737ed4f63e75f6255010d17af818c943daf9d90df445f91e018`.
  The bundle declares macOS 15.0, hardened runtime, the exact approved
  application identifier and Keychain group, and the same profile expiring
  2026-09-29T09:52:27Z. Its fixed read-only probe returned
  `gate_metadata_valid=true`. It launched as PID 55204 from the exact signed
  bundle; the visible UI reported `Activity agent ready`, `Login Item
unavailable`, and `Notifications not requested`. The window was closed to
  leave the process running hidden for the final-source idle measurement.
- A 60-second-warmed, 15-minute hidden-process sample of the immediately
  preceding signed candidate recorded 0.00055% average process CPU, about
  1.00 package idle wakeup/minute, about 58.89 process interrupt
  wakeups/minute, and -1.91 MiB endpoint RSS change. This is diagnostic only:
  the final directory durability call was added after that candidate was
  built, and process interrupt wakeups cannot establish the agent thread's
  18/minute limit. A fresh 15-minute run on PID 55204 was therefore required.
- The final-source signed PID 55204 completed a second 60-second-warmed,
  15-minute hidden-process sample: 181 samples over 900.612 seconds recorded
  0.00077% average process CPU, 0.87 package idle wakeup/minute, and 67.82
  process interrupt wakeups/minute. RSS was 75.80 MiB at the first sample,
  peaked at 79.66 MiB (+3.86 MiB), and ended at 65.83 MiB; physical footprint
  changed by +0.89 MiB. The CPU and RSS-growth figures are below their targets,
  but this run did not satisfy the proposal's five-minute warmup. A further
  15-minute sample was started after the same process had run for over 31
  minutes and after Instruments processing ended.
- Apple Instruments `System Trace` first retained only ten seconds despite a
  60-second recording limit. Repeating with an explicit 60-second retained
  window produced a 71.7-second trace. Its named
  `aeterna-activity-agent` thread had 18 `Blocked` to `Runnable`
  transitions during the 40.05-second interval in which that thread appears
  in the exported table, approximately 27 per minute. The sequence follows
  the five-second sample cadence, generally with a second short block and
  reschedule during each sample. This is above the proposal's 18 total agent
  wakeups/minute target. The trace does not by itself identify the blocking
  API. No sampling interval or Keychain gate rule was changed to mask the
  miss; the energy acceptance point remains open.

## 2026-09-28 signed-host continuation

- A shutdown audit found that `LifecycleAppState::flush()` discarded a failed
  health-record save. It now returns an error, marks the agent unhealthy, and
  requests a nonzero process exit on controlled shutdown. Focused regression
  coverage includes an unwritable health directory and a preexisting invalid
  health record. With exact pinned Node 24.21.0, npm 11.19.0, and Rust 1.98.1,
  `npm run check` passed: 26 frontend tests, 133 Rust library tests with one
  intentional one-GiB ignore, two main-binary tests, and 15 vault integration
  tests, plus formatting, Clippy, type, protocol, and production web checks.
  `npm run desktop:build` also passed. The known nonfatal `rust-objcopy`
  missing-`libLLVM.dylib` warning still means release debug stripping is not
  verified.
- The corrected final source was signed with the existing Apple Development
  identity and profile. Its sole arm64 executable has SHA-256
  `ac5d434e21428391ab2e340f83dad9bc0e9243eaebf580188c60bcb73af969ff`.
  Host-context strict signature verification and the fixed read-only
  `--i08-gate-probe metadata` check passed. No replacement certificate was
  needed. The existing embedded profile lists the Mac mini but not the
  macOS 15.5 MacBook Pro; the latter requires a device-inclusive profile.
- A byte-identical copy of the signed app was placed in
  `/Applications/Aeterna-I08-Test.app`; its strict signature and executable
  hash still matched. Its visible UI reported `Activity agent ready` and
  `Login Item unavailable`. Moving from a private user Applications directory
  to system `/Applications` did not resolve that result. A reversible test copy
  with numeric `CFBundleVersion` and `CFBundleShortVersionString` values was
  re-signed and also reported `Login Item unavailable`. The committed
  `0.0.0-dev` bundle version does not meet Apple's numeric short-version
  format, but this experiment shows that version syntax alone does not explain
  the Login Item status. No Login Item was registered or changed.
- The final signed app created and opened an empty synthetic local vault.
  With its activity agent and tray active, the exact Argon2id E benchmark ran
  three warmups and 20 measured derives under the 512 MiB touched pressure
  fixture: p50 287.082 ms, p95 293.028 ms, and maximum 294.993 ms. Its
  maximum resident set size was 277,053,440 bytes, with zero reported process
  swaps and zero page faults. Host swap use fell from 12,098.12 MiB to
  12,090.12 MiB. The fixture reported `pressure_released=true` and exited.
  The pressure process's RSS fell during the run, so the measurement does not
  prove all 512 MiB stayed resident for every derive. The app remained open
  with `Activity agent ready` after the benchmark.

## 2026-09-28 login-item and floor-host continuation

- The final-source current-host energy sample ran after five minutes of warmup:
  181 samples over 900.534 seconds recorded 0.00109% average process CPU,
  0.80 package idle wakeups/minute, and 81.29 process interrupt
  wakeups/minute. RSS started at 85,327,872 bytes, peaked at 90,275,840
  bytes, and ended at 63,602,688 bytes; physical footprint changed by
  +131,072 bytes. The CPU and endpoint/peak RSS-growth targets pass. Process
  interrupt wakeups are not a substitute for activity-agent thread wakeups;
  the separate System Trace observation of approximately 27 named-thread
  wakeups/minute exceeded the then-current 18/minute target.
- Apple's `SMAppService` can report `NotFound` before a main-app Login Item has
  ever been registered. The prior mapping treated this as permanently
  unavailable, hiding the first-enable action. The mapping now presents
  `NotFound` and `NotRegistered` as disabled, retains explicit native failure
  reporting from registration, and treats either status as already disabled
  on an explicit disable. The focused status-mapping test passed.
- A new test bundle with a temporary numeric `0.1.0` version overlay was
  signed using the existing development identity and profile. No repository
  release version or certificate changed. Its sole executable has SHA-256
  `7d45003f11c7dafd34dc3a7a1f97f2e3d3658f2b9f02757ef2cb4daf7724e8f5`.
  Host-context strict signature verification and the fixed read-only
  `gate_metadata_valid=true` probe passed. A byte-identical copy in
  `/Applications/Aeterna.app` launched with `Activity agent ready` and
  `Launch at login disabled`. After explicit approval, the visible control
  registered the Login Item and showed `enabled`; the same control then
  unregistered it and showed `disabled`. No notification prompt appeared.
  The older canonical test bundle was retained in a private temporary backup.
- The 512 MiB synthetic pressure utility now fills and locks its entire
  allocation before reporting readiness, checks its contents before release,
  and unlocks it at cleanup. Under this fixture the pressure process reported
  `pressure_locked=true`, `pressure_resident_bytes=536870912`, and a stable
  524,976 KiB RSS in all 66 samples over the 7.209-second benchmark window.
  The exact Argon2id E run used three warmups and 20 samples: p50 278.976 ms,
  p95 300.361 ms, maximum 321.564 ms. The benchmark process peaked at
  270,480 KiB RSS. The fixture reported `pressure_released=true` and exited.
  This supersedes the earlier touched-allocation result above, whose RSS fell
  during sampling.
- The 60-second Instruments System Trace attributes the extra short
  `Blocked` to `Runnable` transitions on `aeterna-activity-agent` to `secd`
  waking that thread after about 1-4 ms. A timer separately wakes it at the
  five-second sample cadence. This identifies the second wake source as a
  Security daemon reply. A later export of the trace's `thread-narrative`
  table identified the exact blocked call stack as
  `read_unlock_gate` → `SecItemCopyMatching` →
  `securityd_send_sync_and_do` → `xpc_connection_send_message_with_reply_sync`
  → `mach_msg2_trap`, followed by a `secd` wake. The preceding
  `SecTaskCopyValueForEntitlement` call was also visible but was not the
  `secd` reply wait.
  The measured total was about 27 agent wakeups/minute, above the then-current
  18/minute limit; no gate-read or sample cadence was weakened. The owner later
  approved a 30/minute limit, pending a full-length named-thread remeasurement.
- Following that decision, the unchanged signed `/Applications/Aeterna.app`
  process was left with its window hidden for another 60-second-warmed,
  15-minute host-context rusage sample. The 181 samples over 900.926 seconds
  recorded 0.001145% average process CPU, 7.592 package idle wakeups/minute,
  and 60.471 process interrupt wakeups/minute. RSS started at 14,843,904
  bytes, peaked at 19,398,656 bytes (+4.344 MiB), and ended at 18,972,672
  bytes. Physical footprint peaked only 0.234 MiB above its first sample.
  CPU and RSS growth pass their unchanged limits. Package idle and process
  interrupt counts are diagnostic and do not replace named-agent wakeups.
  A concurrent 15-minute System Trace attempt exceeded safe disk headroom
  during Instruments finalization even with only 60 seconds retained, so it
  was stopped. Its exact temporary cache was removed, restoring approximately
  14 GiB available space. The earlier successful 40.053-second named-thread
  interval measured 18 blocked-to-runnable transitions, or 26.96/minute,
  under the newly approved 30/minute limit. A continuous 15-minute named-thread
  count was not obtained from this attempt.
- A later host-context System Trace successfully recorded 902.400 seconds
  (17:58:29–18:13:31 local). Its global thread-state table covered the full
  recording, but the `aeterna-activity-agent` rows retained only the final
  60.139 seconds. That segment contained 25 blocked-to-runnable transitions,
  or 24.942/minute. A lower-overhead Activity Monitor trace with Thread State
  Trace recorded 91.228 seconds but retained only the final 25.351 seconds of
  agent rows: 12 transitions, or 28.401/minute. Both local segments meet the
  revised 30/minute threshold; neither establishes the required continuous
  15-minute named-thread count. The saved traces and exports remain local
  diagnostic evidence. Further trace experiments were stopped pending stable
  implementation and a proportionate measurement method.
- The development host then entered its normal macOS lock screen during idle
  measurement. The fixed test-probe bundle at
  `/private/tmp/aeterna-i08-cleanup-macmini-20260928/Aeterna.app` passed
  host-context `codesign --verify --deep --strict`; its sole executable SHA-256
  was `ec1406f5f9ecc57f25880eddd04a17e62fae855ce1cb30e83d721ebda84bcf5a`.
  Its read-only `--i08-gate-probe metadata` action returned exit 1 and
  `i08_gate_probe_failed=gate_locked` while the host was locked. No probe
  mutation occurred. After the owner unlocked macOS, the same signed read-only
  probe returned `gate_metadata_valid=true` with exit 0, proving access recovered
  without repairing or replacing the gate.
- After confirming the local vault remained locked, the activity agent was
  ready, and Login Item was disabled, the development-host application quit
  through its normal app menu; a host-context process inventory found no
  `aeterna-desktop` process. The same signed fixed probe passed strict bundle
  verification and returned `gate_metadata_valid=true` immediately before its
  exact `delete` action. That action exited 0 with `gate_deleted=true`; a
  separate read-only metadata invocation exited 1 with
  `i08_gate_probe_failed=gate_not_found`. No broader Keychain deletion ran.
  The app's newly generated 96-byte mode-0600 synthetic health record was
  identified by inode and removed; its empty `health` directory was removed.
  The separate vault directory and SQLite file were preserved.
- With explicit approval, the previous signed bundle was AirDropped to the
  macOS 15.5 Apple Silicon MacBook Pro. The received ZIP's SHA-256 matched the
  sent archive (`e2fa27d111efd48eae97ffc255cc33c4f95f4a4d9ffb1f34653c29e22995b282`),
  and `codesign -v --deep --strict` completed successfully on the extracted
  `~/Downloads/Aeterna.app`. Gatekeeper initially rejected its unnotarized
  developer signature. The user approved a per-app System Settings exception
  and completed the MacBook administrator authentication; global Gatekeeper
  settings were not changed. Finder still reported that Aeterna could not be
  opened. A direct `open` attempt reported LaunchServices launch failure with
  underlying POSIX error 153. `spctl -a -v` still returned `rejected`.
  The embedded Personal Team profile lists the current Mac mini but not the
  MacBook, making the transferred candidate unsuitable for floor-host
  acceptance. The launch error itself does not identify the rejected profile
  as its sole cause. About 50 GiB of filesystem space was available at
  preflight. The Mac App Store offered the last compatible Xcode release for
  macOS 15.5; Xcode 16.4 is now installed, its agreement was accepted by the
  user, and the same Personal Team account is signed in.
- Xcode 16.4 on the MacBook created a temporary macOS project with the exact
  `dev.aeterna.desktop.foundation` bundle identifier and its existing Keychain
  Sharing group. The user authorized the profile change and handled the
  Keychain private-key prompt personally. Xcode reported an Xcode Managed
  Profile and `Build Succeeded` for that project. Its embedded development
  profile was AirDropped to the current Mac with explicit authorization. Its
  SHA-256 is
  `95327069fe0509f898a1cc393ab7a88612fe07c69795bd90b037fe3b68ac0808`;
  it expires on 2026-10-05T04:22:09Z, has the exact application identifier
  and permitted Keychain-group wildcard, includes both Apple Development
  certificates, and lists one device distinct from the Mac mini device in
  the old profile. No private key was transferred or existing certificate
  revoked.
- The Mac mini's existing development identity was included in that new
  profile, so it signed an isolated copy of the current numeric-version I08
  test bundle with the MacBook profile. Host-context strict code-signature
  verification passed; the bundle retains the exact app identifier and
  Keychain group, the macOS 15.0 minimum, and only the main executable in
  `Contents/MacOS`. The signed executable SHA-256 is
  `f984715571b86c944e189a9a7e4ca9622212911e038c471043bc731f268a139a`.
  The prepared AirDrop ZIP SHA-256 is
  `0b02ceed1e644802f0e046ee096d988b3492a64a5ec8e9649b1ccdfb6d090a1b`.
  With explicit approval, this exact ZIP was AirDropped to the MacBook Pro.
  The receiving host independently computed the same SHA-256. It was extracted
  into the separate
  `~/Downloads/Aeterna-I08-MacBook-20260928/Aeterna.app` path, preserving the
  previous test app. MacBook-host `codesign --verify --deep --strict --verbose=2`
  reported `valid on disk` and `satisfies its Designated Requirement`. The
  embedded profile hash matched the transferred profile above. Gatekeeper's
  read-only `spctl --assess --type execute` rejected the unnotarized development
  build, and the first `open` displayed the expected Gatekeeper warning. With
  explicit approval, the per-app `Still Open` action was invoked; macOS then
  requested administrator authentication, which the user completed on the
  MacBook. The newly signed app then opened on macOS 15.5. Its first visible
  health state was `Activity agent ready`, `Launch at login disabled`, and
  `Notifications not requested`; it showed the initial local-vault setup form.
  No global Gatekeeper setting was changed. This establishes startup on the
  floor host, not the remaining lifecycle matrix.
- The first MacBook test launch left two translocated Aeterna instances. After
  separate approval to quit, both were closed through the visible Aeterna
  application menu. A MacBook `pgrep -fl Aeterna` check after the second quit
  returned no process. The dock icon also disappeared. The downloaded signed
  test app remains in place; no Login Item or notification state was changed.
- A renewed host-context, fixed read-only probe on the Mac mini's installed
  signed bundle returned `gate_metadata_valid=true`. The same command inside
  the restricted execution sandbox returned `gate_keychain_unavailable`, so
  the host-context result is the valid current-state evidence. No gate
  mutation was attempted.
- After separate approval, the MacBook copied that exact signed bundle to the
  previously absent `/Applications/Aeterna.app` path. MacBook-host strict
  `codesign` verification passed there. The executable SHA-256 remained
  `f984715571b86c944e189a9a7e4ca9622212911e038c471043bc731f268a139a`,
  and the embedded profile SHA-256 remained
  `95327069fe0509f898a1cc393ab7a88612fe07c69795bd90b037fe3b68ac0808`.
  After separate launch approval, `open /Applications/Aeterna.app` opened the
  expected window without a new Gatekeeper prompt. The visible initial state
  was `Activity agent ready`, `Launch at login disabled`, and `Notifications
not requested`; the local vault was still on its initial setup form. With
  separate approval, the visible `Launch at login` control changed the status
  to `enabled` and macOS displayed an `Aeterna` login-item-added notification.
  The same control was then used to unregister it, and the visible status
  returned to `disabled`. No extra System Settings approval was required and
  notification authorization was not requested. A later MacBook `pgrep -fl
aeterna-desktop` check identified the running process under
  `/private/var/folders/.../AppTranslocation/.../Aeterna.app`, and the standard
  bundle retained `com.apple.quarantine`. Therefore the visible startup and
  Login Item status transitions above are valid app behavior observations but
  **do not establish standard-path launch or login-session launch**. The
  standard-path case must be repeated after a narrow correction.
- After the translocated process was terminated with `SIGTERM`,
  `pgrep -fl aeterna-desktop` returned no process. The exact installed bundle's
  root `com.apple.quarantine` attribute was removed without changing global
  Gatekeeper settings. A subsequent `xattr -p` reported no such attribute and
  MacBook-host `codesign --verify --deep --strict --verbose=2` again reported
  `valid on disk` and `satisfies its Designated Requirement`. Launching with
  `open -n /Applications/Aeterna.app` then produced PID 71568 at the exact
  `/Applications/Aeterna.app/Contents/MacOS/aeterna-desktop` path. The visible
  agent was ready and Login Item status was disabled. UU remote displayed the
  window but initially did not deliver desktop clicks, so the standard-path
  registration/rollback could not yet be verified. The
  installed bundle's fixed read-only `--i08-gate-probe metadata` invocation
  returned `gate_metadata_valid=true` on the MacBook host.
- With the standard-path PID 71568 still running, the user clicked the focused
  app's `Launch at login` control on the MacBook when UU did not forward
  automated clicks. macOS displayed the `Aeterna` login-item-added notice.
  Reopening the same process from `/Applications/Aeterna.app` showed `Launch
at login enabled` and the `Stop launching at login` control. After remote
  input recovered, that control was clicked once and the status returned to
  `Launch at login disabled`; a second observation confirmed it remained
  disabled. This completes the standard-path registration/rollback case,
  without establishing an actual logout/login launch.
- On that same standard-path MacBook process, closing the initial vault-setup
  window left the Aeterna application active. Selecting its Dock icon reopened
  the setup window with `Activity agent ready` and `Launch at login disabled`.
  This covers close/reopen without an unlocked vault or in-flight transfer;
  those cases remain separate.
- On the MacBook, invoking the visible `Enable notifications` control changed
  the app status from `Notifications not requested` to `Notifications denied`.
  No explicit Allow or Deny selection was observed in the delayed UU remote
  display, so the exact OS prompt transition is unverified. The app no longer
  presented the first-use button, and System Settings listed Aeterna under
  application notifications with `Allow Notifications` off. After remote
  control recovered, changing that exact System Settings switch to on made the
  focused Aeterna app report `Notifications authorized`. Changing it back to
  off made the app report `Notifications denied` again. The switch does not
  restore the original `not requested` state; no broader notification database
  reset was attempted.
- The user then explicitly authorized all operations needed to finish this
  task without repeated per-step requests. Subsequent native mutations are
  recorded under that task-specific instruction; system credentials and legal
  agreements still remain user-operated.
- The remaining Mac mini synthetic-gate cleanup failure was traced to
  `kSecUseAuthenticationUISkip` in the feature-gated update and delete query.
  Apple's Security documentation permits that option only with
  `SecItemCopyMatching`. The shared mutation query no longer includes it;
  the query regression test passed, and the complete `npm run check` passed
  with 135 Rust library tests, one intentional one-GiB ignore, 26 frontend
  tests, two main-binary tests, and 15 vault integration tests. The official
  `llvm-tools` component was added to the pinned Rust 1.98.1 toolchain;
  `rust-objcopy --strip-debug` then succeeded on the fixed arm64 binary.
  An isolated Mac mini bundle was signed with the existing identity and
  profile, and host-context strict signature verification passed. After the
  running Aeterna exited normally, the signed probe first returned
  `gate_metadata_valid=true`, then `gate_deleted=true`, and an independent
  read-only probe returned `gate_not_found`. No broader Keychain query or
  deletion was used. A separate MacBook-profile cleanup bundle was strictly
  signed and verified for the floor host;
  its ZIP SHA-256 is
  `a8ea6798c7c35e654cad6909efc32907d2e228a06f0e68ea64abf2a171dd46b0`.
- UU remote input and display became delayed while inspecting the MacBook
  notification panel. The computer-control interface reported that the current
  Mac had locked and could not be automatically unlocked. The owner unlocked
  it, and the MacBook notification Settings refresh above then completed.
- On the MacBook, clicking the Aeterna window close control hid the window while
  the app remained active in the macOS menu bar. Clicking its Dock icon restored
  the same setup window, with activity agent ready, Login Item disabled, and
  notifications denied. This verifies ordinary close/reopen only; the
  unsaved-edit, transfer, tray-menu, and vault-lock branches are still open.
- On the current macOS 26.3 host, the strictly verified
  `/Applications/Aeterna.app` with executable SHA-256
  `7d45003f11c7dafd34dc3a7a1f97f2e3d3658f2b9f02757ef2cb4daf7724e8f5`
  launched from the exact standard path as PID 78452. Its existing synthetic
  vault was locked, the activity agent was ready, and Login Item remained
  disabled. The app-menu `Quit Aeterna` action ended that process; a process
  inventory found no Aeterna executable. Relaunching the same bundle reopened
  the vault in the locked state with the activity agent ready. This verifies
  normal quit/relaunch with an already locked vault, without an in-flight
  transfer or unsaved edit.
- The owner created a synthetic local vault on the MacBook and kept its test
  master password private. The visible app showed an unlocked empty vault and
  activity agent ready. A synthetic note was drafted. Closing the main window
  presented `Discard unsaved changes?` with Cancel, Save, and Discard actions.
  Cancel kept the window, draft title, and draft body intact. A second close
  followed by Save hid the window while Aeterna remained active. Reopening the
  same process from the Dock showed `Unlock your local vault`, an empty
  password field, activity agent ready, and Login Item disabled.
- After owner-entered unlock, the saved synthetic note title and body both
  reappeared. A distinct temporary body marker was added without saving;
  selecting New item presented the unsaved-changes confirmation. Discard
  returned to a blank new editor, and selecting the saved note showed its
  original body without that marker. Another distinct unsaved marker was then
  added to the note, and the macOS Apple menu's Lock Screen action displayed
  the actual MacBook lock screen. After the owner authenticated to macOS,
  Aeterna's main window was hidden while its app remained active. Reopening
  it from the Dock showed the locked-vault password form, activity agent ready,
  and Login Item disabled. This verifies screen-lock vault clearing from the
  UI. After another owner-entered vault unlock, the saved body reappeared
  without the temporary marker, confirming that the screen-lock path discarded
  the unsaved edit. Keychain gate unavailability while locked was not
  independently probed in this run.
- An initial MacBook `pmset sleepnow` attempt returned IOKit error
  `0xe00002e2`. `pmset -g` then showed the pre-existing system-wide
  `SleepDisabled=1`; UU Remote also held an idle-sleep assertion. After the
  owner authenticated a temporary `sudo pmset -a disablesleep 0`, a fresh
  `pmset -g` showed `SleepDisabled=0`. With a distinct unsaved synthetic body
  marker in Aeterna, `pmset sleepnow` printed `Sleeping now...`; the UU Remote
  host became offline and then reconnected after wake. The original Aeterna
  process remained running, but reopening its window showed the locked-vault
  form, an empty password field, and a ready activity agent. The owner then
  authenticated `sudo pmset -a disablesleep 1`, and `pmset -g` independently
  confirmed that the original `SleepDisabled=1` was restored. A precise
  power-log sleep/wake pair has not yet been captured. After owner-entered
  vault unlock, the saved note's body was exactly its original synthetic text;
  the distinct unsaved sleep marker was absent.
- The repository-owned floor-host KDF ZIP was AirDropped to the MacBook Pro.
  Its received SHA-256 was
  `aef05b712af634b6125e92bff016fbee02e3f0043150a03cf5b43abdf045a1a3`.
  The extracted pressure and Argon2 benchmark binaries matched their source
  SHA-256 digests. Gatekeeper initially blocked the pressure binary; the owner
  used the single-binary exception in Privacy & Security. No global Gatekeeper
  setting changed. The successful rerun used the exact accepted 262144 KiB,
  two-iteration, one-lane Argon2id profile, three warmups, and 20 samples with
  a locked, resident 512 MiB pressure allocation while Aeterna was active.
  It reported p50 373.645 ms, p95 377.641 ms, max 380.916 ms, 272023552-byte
  maximum benchmark RSS, zero swaps and page faults, a stable pressure RSS of
  525600 KiB over 87 samples, unchanged 6.69 MiB system swap use, and
  `pressure_released=true`. The floor-host KDF targets pass.
- For the MacBook login-launch cycle, the visible Aeterna control changed
  Login Item from disabled to enabled. macOS's logout confirmation was shown,
  with "Reopen windows when logging back in" unchecked; the test session then
  ended and UU Remote disconnected. The remote session later reconnected to a
  desktop with no Aeterna window. Before the agent manually opened Aeterna,
  its Dock icon showed a running indicator; a subsequent MacBook process
  inventory identified one standard-path `aeterna-desktop` PID 90069, distinct
  from pre-logout PID 71568. This supports hidden Login Item launch rather
  than window restoration. The owner had interacted with the MacBook after
  login, so the vault's immediate post-login locked state was not independently
  observed. The visible Aeterna control then changed Login Item back to
  disabled; the synthetic vault was explicitly locked and the empty password
  form was observed. Tray presence and a precise process start timestamp
  remain unverified.
- A MacBook-profile, strictly verified, feature-gated cleanup ZIP was prepared
  on the development host at 3,477,412 bytes with SHA-256
  `a8ea6798c7c35e654cad6909efc32907d2e228a06f0e68ea64abf2a171dd46b0`.
  Its first AirDrop attempt to the named MacBook Pro reported `rejected` in
  the sender UI. No received-file verification or gate cleanup is claimed
  from that attempt. A later retry showed `sent` in the sender UI and the
  MacBook Downloads window showed `Aeterna-I08-cleanup-signed.zip` at 3.5 MB.
  Finder extraction produced `Aeterna 2.app` beside the existing downloads
  app. After UU Remote stopped forwarding keyboard input, macOS Screen Sharing
  connected to the MacBook. The owner entered the Screen Sharing password on
  the current Mac; no password was sent through the task. On the MacBook,
  `shasum -a 256` matched the sender's ZIP digest, the executable digest
  `080eb150f4d6c7daefd0d676317594624b248cab3187cef77a8856ada28c6951`,
  and the embedded profile digest
  `95327069fe0509f898a1cc393ab7a88612fe07c69795bd90b037fe3b68ac0808`.
  Host-context `codesign --verify --deep --strict --verbose=2` reported `valid
on disk` and `satisfies its Designated Requirement`. Gatekeeper initially
  blocked the unnotarized extracted bundle. After its single-app exception,
  the fixed probe returned `gate_metadata_valid=true`. The app was then quit
  normally; `pgrep -fl aeterna-desktop` showed no process. A fresh fixed probe
  returned `gate_metadata_valid=true`, its exact deletion returned
  `gate_deleted=true,gate_not_found=false`, and an independent metadata probe
  returned `i08_gate_probe_failed=gate_not_found`. No broader Keychain query or
  deletion was used.
- With the MacBook vault unlocked by the owner, a fast user switch from the
  original session to a newly created standard test account `sky` and back
  returned the original Aeterna window to the locked-vault form. The activity
  agent was ready and Login Item disabled; no Aeterna window was observed in
  the test account. The Guest User fallback stayed off. The account owner
  explicitly confirmed `sky` was disposable and approved removal of its home.
  The account was removed from Users & Groups, and `id sky` returned no such
  user. Its logged-in `gui/502` domain initially recreated home subdirectories
  after deletion. `launchctl bootout gui/502` ended that domain; an independent
  `launchctl print gui/502` then failed because the domain no longer existed.
  The exact `/Users/sky` residual directory was removed and `ls -ld` returned
  no such file or directory. Guest User was visually verified off, and the
  Fast User Switching menu-bar preference was restored to its initial
  `Not Shown` value.
- Work then returned to implementation-first sequencing at the owner's
  direction. A custom Quartz probe was abandoned before compilation or
  execution on the MacBook; an unfinished `ed` buffer was quit without saving.
  No remote-input classification claim is based on that attempt. The signed
  MacBook Aeterna test app was subsequently visible with the vault unlocked,
  so final app exit, Keychain-gate cleanup, and
  application-support cleanup are not claimed at this checkpoint.

## Implemented scope

- one supervised, bounded activity worker with capacity-32 nonblocking native
  callbacks, sticky overflow failure, five-second sampling, fail-closed vault
  locking, startup/candidate cooldowns, and non-persisted candidates;
- an exact runtime-derived Keychain access group and fixed, non-synchronizable,
  WhenUnlockedThisDeviceOnly activity-gate identity validated on every read;
- a dedicated `i08-native-probe` test-build feature with fixed,
  non-parameterized metadata, same-value update, and preflight-validated
  exact-delete operations;
  production builds contain no gate mutation entry point;
- explicit Cargo binary declarations and an `engineering-tools` feature gate
  that keep historical I02/I04 command-line probes out of ordinary and I08
  application bundles while retaining opt-in engineering access;
- the 96-byte checksummed `activity-health-v1.bin` format, retained directory
  descriptor, descriptor-relative no-follow operations, private modes, atomic
  replacement, explicit reset, and hostile-file tests;
- public `SMAppService`, direct UserNotifications status/permission handling,
  a localized Tauri tray, hidden Login Item launch, close-to-lock-and-hide,
  reopen/focus, and ordered shutdown;
- five narrow lifecycle commands, strict request/response validation, focused
  visible-window checks for mutations, window-scoped capabilities, strict CSP,
  macOS 15 deployment floor, and unwind release panic behavior; and
- English and Simplified Chinese lifecycle facets and explicit settings UI.

I08 deliberately keeps the service facet unbound and never writes a successful
heartbeat timestamp. Only a future authenticated server acceptance path may do
that.

## Automated evidence

The latest repository state was verified on 2026-09-27 with the pinned Rust
1.98.1 toolchain:

- `npm run check` passed. This included Prettier, ESLint with zero warnings,
  TypeScript type checking, 23 Vitest tests, the production Web build, the
  no-remote-assets check, Rust formatting, all-target/all-feature Clippy with
  warnings denied, 103 passing Rust library tests with the exact one-GiB
  fixture ignored by design, two passing main-binary probe-parser tests, 14
  passing integration tests, and all-target/all-feature `cargo check`.
- A separate default-feature `cargo check --all-targets --locked` passed.
- Separate default-feature and all-feature `cargo clippy` runs passed with
  warnings denied.
- Separate full `cargo test --all-targets --all-features --locked` runs also
  passed during implementation; the final authoritative counts are the ones
  recorded above from `npm run check`.
- `npm run desktop:build` produced the unbundled, distribution-unsigned host
  executable at
  `src-tauri/target/release/aeterna-desktop`; the frontend production build
  again verified three assets with no remote runtime dependencies. The final
  artifact is arm64 Mach-O with SHA-256
  `880e814766230ce0ac8fab0d72b2956f4f5ffe93ab92f686d913210c0984fcc0`.
- A focused default-feature regression test passed for starting the macOS
  lifecycle runtime only on the first Tauri `Ready` event. The canonical
  all-feature suite intentionally selects the separate activity-prototype path,
  so this default-feature test was also run directly.
- `git diff --check` passed after formatting.

Read-only host preflight identified macOS 26.3 build 25D125 on arm64. The host
executable has only an ad-hoc linker signature, no Team identifier, no bound
Info.plist, and no sealed resources; it is not a signed release-shaped bundle.
Its load commands include the expected AppKit, CoreGraphics, Security,
ServiceManagement, UserNotifications, and WebKit system frameworks.
The initial sandboxed Keychain query incorrectly reported zero signing
identities. A separately approved, read-only host query confirmed one valid
Apple Development identity with its private key; no replacement certificate is
needed. The previously installed macOS development profile belongs to the
earlier `dev.aeterna.desktop.i02-keychain-probe` fixture and expires on
2026-09-28. With separate approval, Xcode automatic signing then reused the
existing identity to register `dev.aeterna.desktop.foundation` and install its
Mac Team Provisioning Profile. A temporary macOS signing fixture embedded that
profile, used the exact main-app application identifier and Keychain access
group, and passed strict code-signature verification without being launched.
The Personal Team profile expires on 2026-09-29, so it is suitable only for the
near-term native validation window and must not be treated as release signing.

The approved I08 test build initially exposed a packaging defect: Tauri treated
the unguarded files under `src-tauri/src/bin` as application binaries and copied
the Windows credential probe into `Contents/MacOS`. The candidate was not
launched. Cargo automatic binary discovery is now disabled, the main binary is
declared explicitly, and every historical engineering tool requires the
`engineering-tools` feature. The rebuilt candidate contains only
`aeterna-desktop` under `Contents/MacOS`.

The first step 1 candidate was the arm64 application bundle at
`/private/tmp/aeterna-i08-signed-build/target/release/bundle/macos/Aeterna.app`.
It has bundle identifier `dev.aeterna.desktop.foundation`, Info.plist and Mach-O
minimum macOS version 15.0, hardened runtime, the exact main-application
identifier and Keychain access group, and the approved embedded development
profile. Host-context `codesign --verify --deep --strict` passed. The main
executable SHA-256 is
`3d91f79733cc122cdbcaf9203473c50144f86933faaf536a3332fab370fc2f7c`;
the embedded profile SHA-256 is
`75da57b2288ae75ede38aa2c56d68b5162c88883e1a17f8d5c7fb50c04f4bc12`.
A fixed read-only metadata invocation exited with `gate_not_found`, confirming
that validation did not create the activity gate or initialize the Tauri UI.

The separately approved step 1 attempt launched that exact candidate as PID 52179. It exited with Rust status 101 after approximately 60 milliseconds,
before presenting a usable window or tray. No system permission prompt appeared;
the fixed signed metadata probe still returned `gate_not_found`, and the
application-support directory contained no health file or other file. The
candidate is therefore superseded and must not be relaunched.

Source inspection established the root cause against Tauri 2.11.6 event-loop
code: `Builder::setup` runs immediately before the `Ready` callback, while the
application previously started `MacAppRuntime` before entering `App::run`.
`MacAppRuntime::start` consequently requested managed lifecycle state before
the setup callback registered it, causing the panic. Runtime initialization now
occurs only on the first `Ready` event and uses `try_state` guards for both
managed states. The focused regression test, the full `npm run check`, and a
release-shaped unsigned `npm run desktop:build` all passed after the fix.

With separate approval, the failed bundle was retained as
`Aeterna-failed-step1.app` and a replacement was signed with the same existing
identity and profile without launch. The replacement contains only
`aeterna-desktop`, has the same exact identifier, entitlements, and macOS 15.0
minimum, and passed host-context strict verification. Its executable SHA-256 is
`a337cdafe757d56baad69fd00db68ffc1222a07b1c10735dd5f0ed126bb2b2a1`; the
unchanged embedded profile SHA-256 is
`75da57b2288ae75ede38aa2c56d68b5162c88883e1a17f8d5c7fb50c04f4bc12`.
The replacement's fixed read-only metadata probe returned `gate_not_found`, so
the rebuild and signing operation did not create the activity gate.

The separately approved retry launched that exact replacement as PID 59439.
The process remained running and presented the expected Aeterna window; the UI
reported that the activity gate was unavailable. No system permission prompt
appeared. The app created the exact synthetic Keychain item and a 96-byte
`activity-health-v1.bin` file. The fixed signed metadata probe then returned
`gate_invalid_metadata`, so the step stopped without any Login Item or
notification mutation. The exact process path was rechecked and PID 59439
accepted a normal `NSRunningApplication.terminate()` request; force termination
was unnecessary. Captured standard output and standard error were empty.

Inspection identified one portability defect: the Data Protection Keychain may
omit `kSecAttrSynchronizable` when its effective value is the default false.
The validator had required an explicitly returned CFBoolean false even though
the creation query had set false. Validation now accepts only an absent field
or an actual CFBoolean false, while still rejecting true, null, and values of
another type. A focused six-test macOS activity suite, all-target/all-feature
Clippy, the full `npm run check`, and a release-shaped unsigned
`npm run desktop:build` passed after the correction. The replacement bundle
predated this source change, so it was retained as
`Aeterna-failed-step1-metadata.app` and must not be relaunched.

With separate approval, a third candidate was built and signed using the same
existing identity and profile without launch. Host-context
`codesign --verify --deep --strict` passed; the candidate is an arm64 hardened
runtime bundle with only `aeterna-desktop` in `Contents/MacOS`, exact main-app
entitlements, bundle identifier `dev.aeterna.desktop.foundation`, and macOS
15.0 in both Info.plist and its Mach-O load command. Its executable SHA-256 is
`48c72e2aa9d612650ef05d32e7566b77cfd441cf64c003ddfe93534451046df2`; the
unchanged embedded profile SHA-256 is
`75da57b2288ae75ede38aa2c56d68b5162c88883e1a17f8d5c7fb50c04f4bc12` and it
expires on 2026-09-29. The fixed read-only metadata probe still returned
`gate_invalid_metadata`. This proves the omitted-false behavior was a valid
compatibility correction but not the only returned-metadata mismatch. The new
candidate is not eligible for launch.

With separate approval, the feature-gated native probe was refined to return
only a fixed mismatch category without returning an attribute value, access
group, or item data. Seven focused activity tests, all-target/all-feature
Clippy, and the full `npm run check` passed. A fourth candidate was then signed
with the same identity and profile and passed the same strict signature,
entitlement, architecture, single-executable, and platform-floor checks without
launch. Its executable SHA-256 is
`9b30c96210fc00373cec6b5e21e2a967099bd0994b2b88f10d4ce2de09420de4`.
The fixed read-only probe returned `gate_invalid_class`, establishing that the
remaining rejection is the validator's expectation that `kSecClass` be repeated
in the returned attributes dictionary. The exact query already selects
`kSecClassGenericPassword`; no Keychain or health fixture was changed. This
diagnostic candidate remains fail-closed and is not eligible for a step 1
launch until the returned-attribute contract is corrected and a later candidate
is separately approved and signed.

With separate approval, the validator stopped requiring `kSecClass` in the
returned dictionary while retaining `kSecClassGenericPassword` as an exact
query condition. The regression fixture now models a returned attribute
dictionary without the class key, while separately asserting that the creation
and identity dictionary carries the correct class. Seven focused activity tests
and the full `npm run check` passed. A fifth candidate was signed with the same
identity and profile and passed strict signature verification without launch.
Its executable SHA-256 is
`09c5140811e81407499dc3ab2efb6bb924bedee73a97c3a59fccc8c3f95c2ece`.
The read-only probe advanced past class validation and returned
`gate_invalid_synchronizable`. The query already fixes
`kSecAttrSynchronizable` to false, but this host's returned representation was
neither absent nor recognized by the current validator as CFBoolean false. No
Keychain or health fixture was changed. This candidate is also ineligible for a
step 1 launch.

With separate approval, the validator stopped interpreting the returned
`kSecAttrSynchronizable` representation. Both creation and read queries still
explicitly set the attribute to false, and a focused regression test asserts
both dictionaries. Returned service, account, access group, accessibility, and
the constant-time fixed value comparison remain enforced. Seven focused
activity tests and the full `npm run check` passed with the pinned Rust 1.98.1
toolchain and bundled Node 24.19.0. The temporary signing directory from the
earlier session had been cleared by the operating system, so its prior candidate
copies are no longer present; their hashes remain in this ledger. The signing
fixture was reconstructed from the recorded exact identity, entitlement, and
profile values without creating or refreshing any certificate or profile.

The sixth candidate at
`/private/tmp/aeterna-i08-signed-build/target/release/bundle/macos/Aeterna.app`
was signed on 2026-09-27 with the same existing identity and profile. It passed
host-context strict signature verification, carries the exact entitlements,
contains only `aeterna-desktop`, and retains macOS 15.0 in both Info.plist and
the Mach-O build command. Its executable SHA-256 is
`6a174c47e437d832a975e78bbe4adad19fa7445b7196dbd98529dfd39662c400`; the
embedded profile SHA-256 remains
`75da57b2288ae75ede38aa2c56d68b5162c88883e1a17f8d5c7fb50c04f4bc12` and
expires on 2026-09-29. The fixed read-only probe returned
`gate_metadata_valid=true`. The app was not launched, and the existing Keychain
gate and 96-byte health fixture were not modified. This candidate is eligible
for a separately approved step 1 retry within the profile's short remaining
validity window.

The user approved that step 1 retry on 2026-09-27. Immediately before launch,
host-context strict signature verification passed again, the executable and
embedded-profile SHA-256 hashes matched the recorded sixth candidate, the
profile expiration was confirmed as 2026-09-29T09:52:27Z, and the candidate's
fixed read-only probe again returned `gate_metadata_valid=true`. The existing
health fixture was still a 96-byte regular file with mode 0600 in a mode-0700
`health` directory. Preflight then found PID 657 running from
`/Users/skybao/Rust/aeterna/src-tauri/target/debug/bundle/macos/Aeterna.app/Contents/MacOS/aeterna-desktop`,
started on 2026-09-24. Its signed bundle identifier is the separate
`dev.aeterna.desktop.i02-keychain-probe`, and its executable SHA-256 is
`d60a9ea6b8f0c4a95ff3e576ec3fae46460e2e9b36a0cb38e1d01d87aa909cd3`.
The runbook requires a separate exact-process termination approval before step
1 when an Aeterna process is present. The sixth candidate was therefore not
launched, and no native fixture or system permission state was changed by this
preflight.

The user separately approved normal termination of PID 657 and continuation of
step 1. Immediately before termination, its executable path was rechecked;
`NSRunningApplication.terminate()` accepted the request, PID 657 exited, and a
process inventory found no remaining Aeterna instance. The exact sixth
candidate was launched through LaunchServices as PID 62019 on macOS 26.3 build
25D125, arm64, host `Mac-mini.local`. Its Aeterna window opened without a
permission prompt and showed `Activity agent ready`, `Login Item unavailable`,
and `Notifications not requested`. The same signed bundle's fixed read-only
probe returned `gate_metadata_valid=true`; PID 62019 remained running from the
expected executable path. The existing health file remained 96 bytes with mode
0600 and its 2026-09-22 modification time; its directory retained mode 0700.
The exact application-support tree contained only that health file. The gate
already existed at the start of this retry, so this attempt validates its
metadata and runtime availability rather than proving first-time creation.
No Login Item or notification state was changed. Cleanup was still pending at
that point.

When the user directed the task to end on 2026-09-27, PID 62019 received a
normal `NSRunningApplication.terminate()` request and exited. The signed fixed
probe validated the gate once more, but its exact `delete` action returned
`i08_gate_probe_failed=gate_native_failure`; a subsequent read-only metadata
probe still returned `gate_metadata_valid=true`. No broader Keychain deletion
was attempted. The sole 96-byte synthetic health file and its now-empty
`health` and application-support directories were removed; a read-only path
check confirmed the application-support directory absent. The signed test
bundle was retained under `/private/tmp/aeterna-i08-signed-build` as evidence
and for a future narrow gate cleanup attempt. No Aeterna process remains
running. The failure's underlying Security.framework status and cause have not
been diagnosed.

Two apparent signature failures were diagnostic false positives. The sandbox
could not see the host trust identity and returned `CSSMERR_TP_NOT_TRUSTED`,
while the deprecated `codesign -d --entitlements :-` syntax misreported the
modern DER entitlement blob as invalid. Host-context strict verification and
the supported `codesign -d --entitlements -` form both passed. The native
runbook now records the authoritative commands.

A subsequent implementation audit found that the gate-creation dictionary did
not yet set `WhenUnlockedThisDeviceOnly`, even though every read correctly
required it. Starting the native matrix at that point would therefore have
produced a known-invalid fixture. The creation dictionary now writes the full
contract, value comparison is fixed-length and constant-time, and the
feature-gated probe provides complete redacted metadata verification plus
preflight-validated, post-verified exact deletion. The full repository check
passed again after this correction and after the engineering-tool bundle gate.
The latter run retained 23 passing frontend tests, 101 passing Rust library
tests with one intentional one-GiB ignore, two passing main-binary parser tests,
and 14 passing integration tests.

The desktop build completed successfully but emitted a toolchain-environment
warning: the installed pinned toolchain's `rust-objcopy` could not load its
adjacent `libLLVM.dylib`, so Cargo could not strip debug information. This did
not prevent the executable from linking, but a release-signing environment
must repair that Rust installation before claiming a clean distributable
artifact. The available bundled Node runtime was 24.19.0 while `package.json`
pins 24.21.0; all commands passed, but the exact Node pin remains an environment
verification gap. The one-GiB I07 fixture remains separately established and
was not materialized merely to claim I08 behavior.

## Native evidence

System-side changes so far are the separately approved Xcode registration and
installation of the main-app Personal Team development profile, the separately
approved terminations of older Aeterna instances, the two stopped step 1
LaunchServices starts, and the successful sixth-candidate launch described
above. The earlier retry left the exact synthetic
activity-gate item in the Data Protection Keychain and left
`/Users/skybao/Library/Application Support/dev.aeterna.desktop.foundation/health/activity-health-v1.bin`
as a 96-byte regular file. The application-support directory was mode 0755,
and its `health` directory and file were modes 0700 and 0600 respectively. At
task stop the file and empty directories were removed, while the exact
Keychain item remained after the narrow deletion failed. No permission prompt,
Login Item mutation, notification mutation, login/logout, screen lock,
sleep/wake, user switch, Screen Sharing session, or clock change occurred.
`I08-macos-lifecycle-native-runbook.md` preserves the remaining validation
procedure if work is resumed.

Read-only current-host preflight found one older ad-hoc Aeterna build already
running from a different worktree. Its executable SHA-256 is
`dca0b9544b37f370270d99185f49838fe1d48dd316497f5d7d72db11116bb656`; it has
no Team identifier or activity-gate entitlement. No Aeterna Login Item or
notification preference record was found, the main-app data directory was
absent, and both the host Keychain CLI and the final signed bundle's fixed
read-only metadata probe reported that the exact activity-gate item was absent.
With separate approval, the old process was matched by both PID and exact
executable path and sent a normal `NSRunningApplication.terminate()` request.
It exited without force termination, and a follow-up process inventory found no
running Aeterna instance. Before the retry, the application-support directory
existed but contained no files; it was retained rather than deleted without
cleanup approval. After the retry it contains only the health fixture described
above. No main Aeterna process remained running at that point; the later
successful sixth candidate also exited normally when the task stopped.

## Unverified acceptance work

- complete the current-host lifecycle matrix and a validly signed Apple
  Silicon macOS 15 floor-host matrix;
- reduce and remeasure named activity-agent wakeups to the accepted target
  without weakening the fixed sampling or gate requirements;
- restore the MacBook's initial `not requested` notification state only if
  macOS offers a narrow application-scoped reset; and
- prove rollback and cleanup for every native fixture before acceptance.
