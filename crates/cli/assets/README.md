# The ScyllaHide profile file this project ships

`scylla_hide.ini` here is the **authoritative** profile file.  Copy it next to
the injector, i.e. into the same directory as `InjectorCLIx64.exe` and
`HookLibraryx64.dll`:

```powershell
copy crates\cli\assets\scylla_hide.ini target\release\
```

## Why the injector cannot be told which profile to use

Measured: the injector is launched as

```text
InjectorCLIx64.exe pid:<pid> <HookLibraryx64.dll> nowait
```

There is **no ini argument**.  `ScyllaHideConfig::ini_path` used to exist and
was never passed to the child process — it was inert.  The only lever is the
`CurrentProfile` key inside the ini the injector finds beside itself, so
profile selection is expressed as *rewriting that key* before injecting.

## The three profiles

| profile | used for | provenance |
|---|---|---|
| `Magicmida` | Themida targets | The historical profile. Kept verbatim, including its gaps, so the three e2e golden gates keep producing the same bytes. |
| `VMProtect x86/x64` | VMProtect targets | The **hook set** is ScyllaHide's own preset from `D:\Tools\ScyllaHide\scylla_hide.ini` (7,223 B). |
| `Disabled` | anything unrecognised | Everything off. |

## Where the VMProtect profile deliberately differs from the vendor preset

The vendor's `[VMProtect x86/x64]` block is tuned for an **interactive
debugger** (x64dbg / Olly / IDA), because that is what ScyllaHide ships into.
This project drives its own CLI debug loop instead, and the existing, verified
Themida profile reflects that.  Six keys are therefore taken from our working
profile rather than from the vendor's:

| key | vendor | here | why |
|---|---|---|---|
| `AutostartServer` | `1` | `0` | The hook DLL would bind `ServerPort` for a ScyllaHide GUI to connect to; a CLI run has no such client. The verified Themida profile already ships `0`. |
| `BreakOnTLS` | `1` | `0` | Debugger-integration behaviour; our loop handles TLS itself. |
| `FixOllyBugs` | `1` | `0` | OllyDbg-specific fixups. |
| `RemoveEPBreak` | `1` | `0` | Our loop sets and removes its own entry-point breakpoint. |
| `SkipEPOutsideCode` | `1` | `0` | Same. |
| `X64Fix` | `1` | `0` | x64dbg-specific fixups; our loop is 64-bit native. |

Everything else — including the hooks that are the point of the profile
(`NtCloseHook`, `NtQueryInformationProcessHook`, `NtQueryObjectHook`,
`NtSetInformationThreadHook`, and the five `Peb*` keys) — comes from the
vendor preset unchanged.

## Verifying a profile actually took effect

The hook library writes `scylla_hide.log` next to itself and logs, per hook,
which ones it applied:

```text
DEBUG: ApplyNtdllHook -> Hooking NtSetInformationThread
DEBUG: ApplyNtdllHook -> Hooking NtQueryInformationProcess
```

A key set to `0` appears only in the `_Nt…` address list, never in a
`Hooking …` line.  So the hooked set is directly assertable from the log
rather than assumed.

## Known gap in the `Magicmida` profile

Measured by comparing it with the vendor's `[Themida x86/x64]` preset, this
profile leaves **off**: `NtCloseHook`, `NtCreateThreadExHook`,
`NtQuerySystemInformationHook`, `PebStartupInfo`, `PebOsBuildNumber`,
`X64Fix`, `BreakOnTLS`.  That may be a real gap in the Themida path.  It is
**not** changed here, because the three e2e gates pin the current behaviour
byte for byte and a profile change must be measured against them first.