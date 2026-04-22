# OSCP Windows Services Script

A PowerShell local-enumeration script for quickly triaging **Windows privilege-escalation opportunities** around services and related execution surfaces.

The script focuses on the things you usually end up checking manually during a local assessment:

- interesting **userland services**
- writable **service binaries** and **parent directories**
- weak **service DACLs**
- **unquoted service paths**
- writable directories that may enable **DLL hijacking / planting**
- interesting **installed software**
- writable **scheduled task** actions

It is designed as a **single-file, no-argument** triage script that prints readable tables to standard output.

## What it does

The script combines service data from **WMI/CIM** and the **registry**, normalizes binary paths, evaluates ACLs with `icacls`, and suppresses noisy driver-style entries so the output stays focused on userland software and potential escalation paths.

It produces these sections:

1. **Services / software**
2. **Installed software**
3. **Unquoted service paths**
4. **DLL hijack candidates**
5. **Scheduled tasks**
6. **Manual verification**

## Why this is useful

On Windows hosts, privesc around services is rarely just “is the service binary writable?”. In practice, you often need to correlate:

- who the service runs as
- whether the service can be restarted by low-priv users
- whether the binary or parent folder is writable
- whether the service path is unquoted
- whether the software looks like third-party or user-installed software
- whether the same writable execution surface also exists in scheduled tasks or PATH directories

This script pulls those checks into one pass so you can spend more time validating real attack paths and less time collecting raw data.

## Features

### Services / software triage

Enumerates local services, merges WMI/CIM and registry-backed metadata, and highlights only rows that are either:

- operationally **actionable**, or
- otherwise **interesting** from a pentest perspective

For each service, the script can show:

- service name and display name
- account used to run the service
- company and product metadata from the binary
- resolved binary path
- whether low-priv principals appear able to restart the service
- service DACL findings
- effective access on the binary itself
- effective access on the parent directory
- a combined `Findings` field

### Installed software inventory

Builds a filtered view of installed software using uninstall registry keys plus top-level Program Files folders. The filter is intentionally biased toward **uncommon / non-Microsoft** software and suppresses obviously noisy Microsoft / Windows entries.

This is helpful for spotting:

- third-party services worth deeper review
- custom line-of-business software
- vendor software installed in writable locations

### Unquoted service path detection

Finds userland services whose binary paths:

- contain spaces, and
- are **not quoted**

It also generates the candidate executable paths Windows may try first and annotates the candidate parent directories with effective write access.

### DLL hijack / planting candidates

Highlights service-backed software where the binary directory is writable, plus any writable machine-level `PATH` directories.

These are not automatically exploitable by themselves, but they are strong triage signals for:

- DLL search-order issues
- DLL planting opportunities
- binary-adjacent persistence or escalation paths

### Scheduled task checks

Enumerates scheduled tasks via `Get-ScheduledTask`, resolves task action binaries, and reports task actions where the binary or parent directory appears writable to the current security context.

It suppresses obvious Windows-noise tasks and skips tasks that already run in the current user context.

### Manual verification hints

At the end, the script prints useful follow-up commands for:

- `sc.exe`
- `reg query`
- `icacls`
- `schtasks`
- `whoami`

That makes it easy to pivot from triage output into manual confirmation.

## Output overview

### `Services / software`

Typical columns:

- `Service`
- `DisplayName`
- `RunAs`
- `Company`
- `Product`
- `Path`
- `CanRestart`
- `SvcRights`
- `BinAccess`
- `DirAccess`
- `Findings`

### `Installed software`

Typical columns:

- `Name`
- `Publisher`
- `Version`
- `InstallDir`
- `DirAccess`
- `Source`

### `Unquoted service paths`

Typical columns:

- `Service`
- `DisplayName`
- `RawPath`
- `ResolvedBinary`
- `CandidateExecutables`

### `DLL hijack candidates`

Typical columns:

- `Service`
- `DisplayName`
- `RunAs`
- `Binary`
- `BinaryDir`
- `DirAccess`
- `WhyInteresting`

and for machine `PATH` issues:

- `PathDir`
- `DirAccess`
- `WhyInteresting`

### `Scheduled tasks`

Typical columns:

- `TaskPath`
- `UserId`
- `State`
- `Execute`
- `Arguments`
- `ResolvedBinary`
- `BinAccess`
- `DirAccess`
- `Findings`

## Findings field guide

The `Findings` column is the fastest way to identify rows worth validating first.

Common values include:

- `software:interesting` — likely non-Microsoft / userland software worth reviewing
- `svc:restart` — the service appears restartable by low-priv principals
- `svc:dacl` — potentially dangerous service-control permissions were identified
- `bin:F`, `bin:M`, `bin:W` — full / modify / write on the binary
- `dir:F`, `dir:M`, `dir:W` — full / modify / write on the parent directory
- `unquoted` — the service path contains spaces and is not quoted

## Service rights guide

The service DACL parser looks for interesting rights granted to common low-priv principals such as:

- `BUILTIN\Users`
- `Authenticated Users`
- `INTERACTIVE`
- `Everyone`

Common service-right codes you may see:

- `RP` — start service
- `WP` — stop service
- `DC` — change service configuration
- `WD` — write DACL
- `WO` — write owner

In practice:

- `RP` + `WP` usually means a user can **restart** the service
- `DC`, `WD`, or `WO` are often stronger signals and should be reviewed immediately

## Requirements

- Windows host
- PowerShell
- access to standard Windows utilities such as `sc.exe`, `reg.exe`, and `icacls`

The scheduled-task section depends on `Get-ScheduledTask`. On hosts where that command is unavailable, the script will tell you that scheduled-task enumeration is not available.

## Usage

Run it directly in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\services.ps1
```

Or from an existing PowerShell session:

```powershell
.\services.ps1
```

Because the script evaluates findings from the **current token**, running it as a normal low-priv user is usually the most useful perspective for local privilege-escalation triage.

## Example workflow

1. Run the script as the compromised or test user.
2. Review `Services / software` for rows with `bin:*`, `dir:*`, `svc:dacl`, or `unquoted`.
3. Check whether `CanRestart` is true for service-binary replacement scenarios.
4. Review `Unquoted service paths` and inspect candidate parent directories.
5. Review `DLL hijack candidates` for writable binary directories and writable machine PATH directories.
6. Review `Scheduled tasks` for writable task-backed executables.
7. Use the built-in manual verification commands before attempting exploitation.

## Limitations

- This is a **triage** script, not an exploitation framework.
- Results are heuristic and should always be manually verified.
- Writable paths are evaluated from the **current user / group token**, so results can differ between users.
- The script deliberately suppresses many Microsoft / Windows / driver-style rows to reduce noise.
- It prints human-readable output only; there is no CSV or JSON export in the current version.

## Notes

- The script is broader than services alone: it also checks installed software, DLL-hijack-adjacent paths, and scheduled tasks.
- Resolved paths are normalized to better handle common Windows path formats such as `%ENV%`, `\SystemRoot\`, and System32/Sysnative edge cases.

## Disclaimer

Use this only on systems you are authorized to assess. Always validate findings carefully before making changes to services, files, permissions, or scheduled tasks.

## License

No license file is currently included in the repository. If you plan to reuse or redistribute this project, add a license first.
