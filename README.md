# Embers: Windows ransomware investigation dashboard

A sister tool to Crumbs. Point it at a Windows system volume (for example a mounted Macrium image) and it
reconstructs what the ransomware did: which files it encrypted and when, what ran before it, what it changed
in the registry, how it persisted, and how the attacker got in. Everything lands in one SQLite file per case
and is explored in a local web dashboard.

Standard library plus Flask. No Sleuth Kit, no compiled parsers: Embers reads NTFS, registry hives,
event logs and prefetch files itself.

## Quick start (Macrium image)

1. **Mount the image read-only.** In Macrium Reflect: *Existing Backups* (or *Restore* → *Browse for an image*)
   → select the `.mrimg` → *Browse Image* / *Explore image* → pick the Windows partition, **leave "Enable write access"
   unticked**, choose a drive letter, e.g. `F:`.
   *Alternative:* *Other Tasks → Convert Image to VHD*, then attach the VHDX read-only
   (`Mount-DiskImage -ImagePath x.vhdx -Access ReadOnly`) and use its drive letter or `\\.\PhysicalDriveN`.
2. **Run as Administrator** (raw volume access needs it):
   ```
   pip install -r requirements.txt
   python app.py \\.\F: --db case-victim01.db
   ```
3. Open http://127.0.0.1:8766. Indexing runs in the background with progress in the top-right corner
   (minutes for a typical workstation, longest on big event logs).

Re-open a finished case later with `python app.py --no-index --db case-victim01.db`.
`start_embers.bat` asks for the drive letter and does step 2 for you.

### Other sources

| Source | Command |
|---|---|
| Mounted volume (best) | `python app.py \\.\F:` |
| Attached virtual disk | `python app.py \\.\PhysicalDrive3` (largest NTFS partition, or `--partition N`) |
| Raw / dd / fixed VHD file | `python app.py D:\cases\disk.raw` |
| Plain folder (no admin) | `python app.py F:\ --mft exported_$MFT --usn exported_$J` (exports optional) |

Raw mode is strongly preferred. It reads `$MFT` and `$UsnJrnl:$J`, which a normal file copy never sees, and
it is not stopped by the ACLs of the imaged system (user profiles, `System Volume Information`). Folder mode works,
but without an exported `$MFT` the Filesystem, Impact and payload analysis are mostly empty.

BitLocker: if the volume was encrypted, Macrium normally images the *unlocked* data. If Embers reports
"$MFT record 0 not found", unlock the mounted volume first (`manage-bde -unlock F: -RecoveryPassword ...`).

Options: `--db` case file, `--port`, `--partition N`, `--reg-days 60` (how far back registry key write times are kept),
`--span-days 14` (how many days before encryption the super-timeline starts).

## What it reads

| Artifact | What you get |
|---|---|
| `$MFT` | every file and folder, including deleted records: `$SI` and `$FN` times, size, alternate streams, Zone.Identifier (download URL), timestomping flags |
| `$UsnJrnl:$J` | creates, renames, overwrites, deletes with the name at that moment: original names of encrypted files, deleted payloads |
| Registry: SYSTEM, SOFTWARE, SAM, SECURITY, every NTUSER.DAT and UsrClass.dat, Amcache.hve | `.LOG1/.LOG2` transaction logs are replayed first; see Registry below |
| `winevt\Logs\*.evtx` | all records, BinXML fully decoded (event IDs, every field); gaps in record IDs |
| `Windows\Prefetch\*.pf` | XP to 11, incl. compressed (MAM) files: last 8 run times, run count, first run, files touched in the first seconds |
| Scheduled tasks | `System32\Tasks` XML plus TaskCache in SOFTWARE; tasks hidden by deleting their SD value |
| User artifacts | Recent/Desktop LNK files, Recycle Bin `$I`, PowerShell PSReadLine history, Chrome/Edge/Firefox history and downloads, RDP client history, typed paths, wallpaper, AnyDesk/TeamViewer connection logs, Defender MPLog |

## The views

- **Overview**: host facts (name, OS build, time zone, IPs, last clean shutdown), the encryption banner,
  a chronological list of key events, payload candidates, the ransom note with extracted IOCs (emails, .onion,
  BTC, Tox, victim ID), local accounts, and what was collected (hive states, event log ranges, USN coverage).
- **Impact**: the ransomware extension (with candidates to correct the guess), an encryption-over-time chart,
  which folders and file types were hit, which documents in those folders were *not* encrypted, every ransom
  note with its text, and the full list of encrypted files with original names. Exportable as CSV.
  You can override the extension or the encryption window and re-analyse.
- **Timeline**: one super-timeline of everything above, for the analysis span. Filter by source and text
  (`-word` excludes); click a histogram bar to zoom in; click a row for full details.
- **Execution**: every program with evidence of running, grouped across Prefetch, Amcache (with SHA-1 →
  VirusTotal link), BAM, UserAssist, ShimCache, RunMRU, Security 4688 and Sysmon 1. Odd locations,
  random names, known attacker tools and suspicious command lines are flagged.
- **Persistence**: services, tasks, Run keys, startup folders, IFEO debuggers, SilentProcessExit, SafeBoot
  entries added after install, WMI subscriptions, services and tasks from event logs.
- **Registry**:
  - *Risky settings*: Defender off or excluded paths, tamper protection, VSS/backup/EventLog services disabled,
    WDigest, AutoAdminLogon with a stored password (the Safe Mode reboot trick), logon banner text,
    EnableLinkedConnections, symlink evaluation, firewall off, UAC, the ransomware extension being registered.
  - *Unflushed changes*: the difference between the hive on disk and the hive after replaying its transaction
    logs. These are the newest registry writes before the image was taken, often exactly what the ransomware set.
  - *Deleted keys*: keys and values recovered from free space in the hives.
  - *Recently written keys*: every key's last-write time in a window (noise filter included).
  - *Browse hives*: a regedit-style browser over the replayed hives.
- **Event logs**: channels, presets (logons, process creation, services, log clearing, PowerShell, Defender,
  RDP, tasks, boot/shutdown), text and time filters.
- **Logons & RDP**: 4624/4625/4648 grouped by account, type and source IP (public IPs highlighted), RDP sessions.
- **Filesystem**: search the MFT; filter executables, deleted records, timestomped files, downloads, ADS;
  open a file to see all eight timestamps, its USN history, and its first 64 KB with entropy.
- **USN journal**, **Findings**, **User artifacts**, **Evidence board** (pins with notes, Markdown case report).

The **UTC / Host time** switch shows all times either in UTC or shifted by the host's current UTC offset from
the registry. Note that offset is the *current* one; daylight saving time on the day may differ by an hour.

## How the ransomware analysis works

- **Extension**: for every unusual extension, Embers measures how often it sits on top of a document extension
  (`report.docx.X`), how many folders it spans, and how tightly its timestamps cluster. Known ransomware
  extensions get extra weight. Phobos/Dharma style `.id[..].[mail].ext` names are recognised.
- **Encryption time**: renaming a file updates its MFT entry-modified time (`$SI` "entry modified"), so that
  time on the encrypted files gives the encryption sequence; USN rename records refine start and end.
  `$SI modified` may or may not change depending on the family, so it is shown but not relied on.
- **Original names**: from USN `RenameOldName` → `RenameNewName` pairs, otherwise by stripping the extension.
- **Ransom notes**: a name created in many folders inside the encryption window, small, text/HTML/HTA.
- **Payload candidates**: executables that ran (any source) shortly before or during encryption, were created
  in the 48 h before it, sit in odd places, have random names, were deleted right after, or whose prefetch file
  list includes encrypted files or the note. Each candidate shows its reasons and a score.
- If no extension change is found (in-place encryption), the busiest burst of document modifications is
  used as the window. Set the window yourself under Impact if that guess is wrong.

## Reading results honestly

- The registry keeps no history of values. You get the current value, each key's last-write time (which
  says *a* key changed, not which value), unflushed changes from the transaction logs, and deleted keys.
- The USN journal is a ring buffer (often 32 MB to a few hundred MB). Mass encryption can push the start of
  the attack out of it; the Overview shows the time range it still covers.
- Event logs may have been cleared (1102/104 findings) or rolled over; missing record IDs are reported.
- ShimCache times are file modification times, not execution times. Amcache times are when the file was
  first inventoried. Prefetch times are real executions (only the last eight are kept).
- Timestamps in `$SI` can be forged; `$FN` times are set by the kernel and much harder to fake.
- Volume Shadow Copies are not read. If any survived, mount them separately (`vssadmin list shadows` on the
  mounted image, or `mklink /d`) and run Embers on each as an extra case to see earlier versions.
- Not parsed: SRUM, WMI repository, Jump Lists, ShellBags, `$LogFile`, memory. Use dedicated tools for those.

## Trying it without evidence

`python tests/make_fixture.py demo.raw` builds a small synthetic NTFS volume with a LockBit-style scenario
(encrypted files, notes, payload, USN journal, hives with a transaction log, an event log, a prefetch file).
`python app.py demo.raw --db demo.db` then shows every view working.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask server and API |
| `indexer.py` | extraction stages, ransomware analysis, timeline |
| `ntfs.py` | raw NTFS: partitions, MFT, data runs, sparse/compressed streams, USN |
| `regf.py` | registry hives, transaction-log replay, diff, deleted keys |
| `evtx.py` | event logs with BinXML templates |
| `winart.py` | prefetch (+ Xpress Huffman), LNK, `$I`, ShimCache, tasks, Amcache, BAM, UserAssist, accounts |
| `rules.py` | detection rules: command lines, events, registry checks, tool names, path heuristics |
| `static/` | dashboard (vanilla JS, Crumbs stylesheet + `embers.css`) |
