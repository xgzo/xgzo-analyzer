# xgzo analyzer

a deep pc check and forensic tool for fivem, roblox, minecraft, and other games. built for screenshares and catching cheaters who think they can wipe their tracks.

dark mode only, because we aint tryna flashbang ourselves at 3am.

## what it does

- **live processes:** scans ram for known executors and cheats. if its running, it dies.
- **filesystem scan:** sweeps appdata, temp, and downloads (or the whole c: drive if u hit full scan). looks for executables, dlls, lua scripts, and cheat folders.
- **browser traces:** pulls chrome, edge, and brave history. checks for cheat downloads and digs into the raw sqlite bytes to find deleted history.
- **mft parser:** reads the raw ntfs master file table to find deleted exes, dlls, and scripts. even if they emptied the recycle bin.
- **amcache & prefetch:** reads windows registry hives and prefetch files to see what ran, when it ran, and where it was.
- **anti-forensics:** detects if they tried to wipe their tracks (usn journal deleted, prefetch cleared).
- **screen share checks:** catches injected dlls in critical processes and flags unsigned executables.

## how to run

u need python installed. open terminal in the folder and run:

    py -m pip install -r requirements.txt
    py main.py

**important:** run as administrator. if u dont, the mft parser and registry checks will fail or skip.

## building the exe

if u wanna carry it on a usb and run it without python:

    py -m PyInstaller --noconfirm --onedir --windowed --name "xgzo-analyzer" --add-data "ui;ui" --add-data "admin.manifest;." --manifest "admin.manifest" --collect-all pytsk3 --collect-all regipy --collect-all pywebview main.py

go to `dist/xgzo-analyzer` and double click the exe. it will ask for admin perms automatically.

## how to use

- hit **quick scan** for a fast check of common cheat paths.
- hit **full drive scan** if u think they hid it deep in the system.
- watch the **execution logs** tab to see exactly what the tool is doing.
- if it finds something, the card turns red. click the card and it opens the file path for u.

## notes

if the usn journal is wiped or prefetch is cleared, the tool will scream at you. a clean pc doesn't need to wipe its own logs. 

made by xgzo, please report bugs and send feedbacks