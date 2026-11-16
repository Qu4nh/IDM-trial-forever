# IDM Trial Forever

An experimental Windows launcher with a CMD control menu for viewing and managing IDM's local trial state.

## Disclaimer

**This project is intended for learning, research, and educational purposes only.** It is independent of Tonec and the Internet Download Manager developers. It does not provide an IDM license or guarantee permanent activation. An educational purpose does not override the software's license terms or applicable rules. For supported continued use, obtain a license from [the official vendor](https://www.internetdownloadmanager.com/).

The tool modifies local Registry data and is provided **as is, without warranty**. Review the source and keep backups. The remaining-day display is an estimate: an expiry popup may still occur even when the managed counter is zero. This runtime issue remains unresolved; do not assume the tool prevents every popup.

## Requirements

- Windows x64 and Python 3.10+ from [python.org](https://www.python.org/downloads/windows/).
- An existing IDM **6.43 build 18**, file version `6.43.18.2`, matching this exact SHA-256:

```text
A705C0154FAFC7CD509DECF165CB6F6C050B6521B40ADB6F730DD827C86051C7
```

Other executable hashes require the manual verification flow below before writes are allowed. The read-only `--analyze` survey accepts other Windows PE builds. No third-party Python packages are needed.

## Automatic discovery and renewal

The trial GUID is no longer hardcoded. For the exact supported executable, the tool extracts literal CLSID paths from its bytes, checks the native and WOW6432Node current-user locations, and validates the expected field names, types and bounds. It selects a key only when exactly one referenced key matches; unrelated COM subkeys, ambiguous matches, unreadable references and unsupported binaries are refused. This does not establish compatibility with all IDM versions or discover every licensing mechanism.

Opening IDM through the launcher performs this cycle automatically: **verify build → discover key → read counter → back up → reset when due → read back and verify → open IDM**. A failed write/readback attempts rollback. Discovery is read-only and can be inspected with:

```powershell
py -3 src/idm_trial_forever.py --discover
```

To survey another build without executing it or modifying Registry:

```powershell
py -3 src/idm_trial_forever.py --analyze --idm-path "D:\Apps\Internet Download Manager\IDMan.exe"
```

The survey extracts ASCII and UTF-16 literal CLSID paths, reads matching current-user keys and reports schema candidates, inaccessible paths and the executable hash. It does not invoke REA or perform runtime reverse engineering. A matching schema does not prove that a key controls the trial; computed or encrypted paths may be missed. Unknown builds require explicit user attestation and a manual test before automatic changes. The known reset profile does not establish successful trial extension: expiry notices on the installed build remain unresolved. **Automatic reset across all IDM versions is not implemented.**

## Everyday use

Open `Open-IDM.cmd` and choose **1 — Open IDM**. The main menu shows whether a local profile is available; technical tools live under **6 — Advanced**. If the version is unsupported, its data needs review, or a manual test is pending, opening IDM leaves its trial data unchanged and renewal is unavailable. You can still use the original IDM normally, subject to its actual license/trial status.

Profiles are explicitly labelled **experimental**. A built-in profile and a user-confirmed profile are not proof of successful trial extension. In particular, the installed build has shown expiry notices despite a zero managed counter. The tool does not describe either profile as independently verified. Changing executable versions or unexpected Registry data stops trial writes rather than selecting a key by guesswork.

## Manual verification (advanced)

Choose **6 — Advanced → 3 — Manual verification / test / revoke**, or run `python src/idm_trial_forever.py --verify`. This flow requires technical knowledge; ordinary users should leave an unsupported build unchanged. All prompts are in English. This is an experimental, user-attested profile, not independent verification or a universal reset mechanism. The wizard only saves local settings; a test write happens solely when you enter `TEST` or explicitly run `--apply`.

1. Turn **popup auto-close OFF** with menu 5. Finish downloads before closing IDM. Run the survey and note the candidate path and hash.
2. Observe the original IDM accessing the exact candidate Registry values. [Microsoft Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) can record Registry activity: filter for `IDMan.exe` and the candidate GUID, then open/use/exit IDM normally. Look for successful reads/writes to the specific values, checking the process path and user. Native and WOW6432Node paths can appear differently; confirm the same physical HKCU key. A string match or `NAME NOT FOUND` event is insufficient. Do not disable security controls if the observer is blocked.
3. Independently check that the **existing algorithm** fits this build: `Model` is a zero-based day-of-year marker, `Therad` is elapsed days, the limit is 30, optional `MData` belongs to that trial state, and the increment logic matches `projected_elapsed()` in the source. Process Monitor shows accesses; it does **not** establish these meanings. This step may still require source/disassembly analysis. If you cannot establish them, cancel instead of guessing.
4. In Advanced → Manual verification, choose the candidate number, enter `OBSERVED` and `SAME SCHEMA` only if those statements are true, and describe your evidence. A **testing** profile is saved. Automatic renewal remains blocked. No Registry values have been changed yet.
5. Exit IDM completely, including the tray process. Return to Advanced → Manual verification and enter `TEST` to run one backed-up test write, or run `python src/idm_trial_forever.py --apply`. The normal schema, process, backup, readback and rollback checks still apply. The test does not open or close IDM for you.
6. Open the **original IDM shortcut**, with auto-close still OFF. Check IDM's own trial behavior, exit/reopen it, and test a normal download. The launcher's estimated counter, a successful Registry write or absence of a popup alone does not establish successful trial extension. If IDM exposes no reliable outcome, leave the profile pending. Return to Advanced → Manual verification: enter `WORKED` and describe actual before/after behavior only if the outcome is supported; enter `FAILED` otherwise. No automatic expiry cycle is proven by this short test.

After `WORKED`, automatic checks may use **only that exact executable SHA-256 and selected key**. Updates require new verification, and schema drift or unreadable references still stop writes. Choose Advanced → Manual verification and enter `REVOKE` to remove your approval. `FAILED`/`REVOKE` remove the local profile; they do not undo a previous test write. Keep the recorded JSON backup for recovery and turn the tool off with menu 2 if results are uncertain. Approval, evidence and test outcome stay in `.idm-tool/config.json` and are excluded from the repository/ZIP. No evidence is uploaded.

If renewal is due while IDM is running, one short-lived helper waits on the exact process handle. It performs the normal discovery/backup/reset checks after IDM exits. It does not poll or interrupt downloads. Disabling the tool cancels the wait. A deferred failure is retained in local settings for `--diagnostics`; permissions/security settings are never changed automatically. Read-only discovery was checked on the installed build; the reset, ambiguity, schema, backup/rollback and deferred behavior were checked with isolated fixtures and controlled processes. A new full natural trial cycle has not been verified.

## Run

Download **Code → Download ZIP**, extract it, then double-click **`Open-IDM.cmd`**. Keep the `src` directory beside it.

| Menu | Action |
| --- | --- |
| 1 | Open IDM, checking the managed trial state first when enabled |
| 2 | Toggle the tool on or off |
| 3 | Refresh status |
| 4 | Check/renew when at most two estimated days remain |
| 5 | Start/stop expiry-notice auto-close after approximately one second |
| 6 | Advanced: read-only diagnostics, survey and manual verification |
| 0 | Exit the menu |

The tool defers trial-state changes while IDM is running and queues due renewals until it exits completely, including its tray process. It does not kill downloads, patch the executable or install a schedule.

### Optional popup auto-close

Choose **5** to enable auto-close. A separate hidden Python worker follows the current IDM process; closing the menu does not stop it. When IDM exits completely, Windows signals its process handle and the worker removes its hook and exits. Closing IDM to the system tray is not a process exit.

The preference is remembered. Subsequent opens through this launcher's **Open IDM** option start the worker automatically. Opening IDM directly through its original shortcut does not start the worker; open the menu to enable it for that session. This tool does not install a Windows startup entry, service or schedule.

The worker waits for window-show events instead of polling. It waits approximately one second, checks the target PID and executable path, exact dialog title, English expiry text and OK button, then clicks OK. Only `IDM has not been registered for 30 days. Trial period is over.` is matched. Purchase windows, download-complete dialogs and other languages/messages are left alone. This dismisses a notice; it does not make an expired trial valid.

Choose **5** again to disable the remembered preference and stop the worker. Disabling the tool also stops it. A kernel event wakes the worker to stop immediately. One Python worker consumes RAM; zero resource use is not promised. A short idle check previously reported 0.0 CPU seconds over six seconds. Controlled tests confirmed approximately 1.06-second dismissal, preservation of unrelated dialogs, and automatic worker exit with its target process.

When disabled, opening IDM through the menu does not access Registry. Disabling does not undo prior changes. Settings are saved locally in `.idm-tool/config.json`; backups are saved before writes in `idm-trial-backups/`. Keep these files private. Backups are JSON records, not directly importable `.reg` files.

For a custom installation path:

```powershell
py -3 src/idm_trial_forever.py --menu --idm-path "D:\Apps\Internet Download Manager\IDMan.exe"
```

The menu uses a compact English interface. Paths, hashes and Registry details are kept in Advanced and the diagnostic/survey CLI commands.

Other commands: `--status`, `--enable`, `--disable`, `--launch`, `--auto`, and `--apply`. Running with no options previews without writing. `--auto` performs one check and exits; `--apply` explicitly requests a reset while IDM is closed.

## License

Copyright © 2024 Qu4nh. Project source is distributed under the [MIT License](LICENSE). This license does not apply to IDM.
