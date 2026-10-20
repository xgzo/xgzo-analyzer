import os
import psutil
import datetime
import hashlib
import subprocess
import sqlite3
import shutil
import tempfile
import ctypes
from pathlib import Path

from screenshare_analyzer import ScreenshareAnalyzer

# ==========================================
# ADMIN CHECK
# ==========================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

try:
    import pytsk3
    HAVE_TSK = True
    TSK_ERROR = ""
except Exception as e:
    HAVE_TSK = False
    TSK_ERROR = str(e)

try:
    from regipy.registry import RegistryHive
    HAVE_REGIPY = True
except ImportError:
    HAVE_REGIPY = False

class API:
    def __init__(self):
        self.sysroot = Path(os.environ.get("SystemRoot", "C:\\Windows"))
        self.user_dir = Path(os.path.expanduser("~"))
        self.local = self.user_dir / "AppData\\Local"
        self.roaming = self.user_dir / "AppData\\Roaming"
        
        self.strict_names = {
            "real", "wave", "delta", "awp", "krnl", "xeno", "evon", 
            "solara", "fluxus", "synapse", "redengine", "eulen", 
            "nexus", "script-ware", "scriptware", "wearedevs", "jjsploit"
        }
        
        self.url_keywords = [
            "redengine", "synapse", "krnl", "fivem cheat", 
            "roblox executor", "mmvi", "xgzo"
        ]

    def _is_cheat(self, path_obj):
        if isinstance(path_obj, str): path_obj = Path(path_obj)
        if path_obj.stem.lower() in self.strict_names:
            return True
        for part in path_obj.parts:
            if part.lower() in self.strict_names:
                return True
        return False

    def _get_hash(self, filepath):
        try:
            if not os.path.isfile(filepath) or os.path.getsize(filepath) > 100 * 1024 * 1024:
                return "Too Large"
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return "Hash Error"

    def start_scan(self, scan_mode="quick"):
        findings = []
        logs = []

        def log(msg):
            logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

        log(f"Initiating PC Check (Mode: {scan_mode.upper()})...")
        
        if not is_admin():
            log("WARNING: Tool is NOT running as Administrator. MFT & Registry will fail.")
        else:
            log("SUCCESS: Running with Administrator privileges.")

        # ==========================================
        # 1. ANTI-FORENSICS & SCREENSHARE CHECKS
        # ==========================================
        log("Running screenshare-specific checks...")
        ss_analyzer = ScreenshareAnalyzer()
        findings.extend(ss_analyzer.run())

        # ==========================================
        # 2. LIVE PROCESSES
        # ==========================================
        log("Scanning live processes for known cheats...")
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe = proc.info['exe'] or ""
                name = proc.info['name'] or ""
                if exe and self._is_cheat(exe):
                    findings.append({"severity": "CRITICAL", "category": "LIVE PROCESS", "artifact": name, "path": exe, "hash": self._get_hash(exe), "timestamp": "RUNNING NOW"})
                    log(f"FOUND: {name} running in memory.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # ==========================================
        # 3. FILESYSTEM SCAN (Quick or Full)
        # ==========================================
        if scan_mode == "full":
            log("Scanning ENTIRE C: drive. This will take a minute...")
            search_dirs = [Path("C:\\")]
            skip_dirs = {"windows", "winsxs", "system32", "syswow64", "microsoft", "packages", "node_modules", "$recycle.bin", "system volume information", "assembly"}
        else:
            log("Scanning Quick Paths (AppData, Temp, Downloads)...")
            search_dirs = [self.user_dir / "Downloads", self.user_dir / "Desktop", self.local, self.roaming, Path(os.environ.get("TEMP", ""))]
            skip_dirs = {"packages", "microsoft"}

        target_exts = {".exe", ".dll", ".lua", ".asi", ".rpf", ".sys"}

        for s_dir in search_dirs:
            if not s_dir.exists(): continue
            for root, dirs, files in os.walk(s_dir):
                dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
                for d in dirs:
                    if d.lower() in self.strict_names:
                        findings.append({"severity": "CRITICAL", "category": "CHEAT FOLDER", "artifact": d, "path": os.path.join(root, d), "hash": "Folder", "timestamp": "ON DISK"})
                        log(f"FOUND folder: {d}")
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in target_exts and Path(f).stem.lower() in self.strict_names:
                        full_p = os.path.join(root, f)
                        findings.append({"severity": "CRITICAL", "category": "CHEAT EXECUTABLE", "artifact": f, "path": full_p, "hash": self._get_hash(full_p), "timestamp": "ON DISK"})
                        log(f"FOUND file: {f}")

        # ==========================================
        # 4. BROWSER HISTORY & DOWNLOADS
        # ==========================================
        log("Scanning Browser Histories & Downloads...")
        chromium_paths = {
            "Chrome": self.local / "Google\\Chrome\\User Data\\Default\\History",
            "Edge": self.local / "Microsoft\\Edge\\User Data\\Default\\History",
            "Brave": self.local / "BraveSoftware\\Brave-Browser\\User Data\\Default\\History"
        }
        
        for b_name, b_path in chromium_paths.items():
            if not b_path.exists(): continue
            tmp_db = Path(tempfile.gettempdir()) / f"{b_name}_hist.db"
            try:
                shutil.copy2(b_path, tmp_db)
                
                with open(tmp_db, "rb") as f:
                    raw_data = f.read().lower()
                    for kw in self.url_keywords:
                        if kw.encode() in raw_data:
                            findings.append({"severity": "HIGH", "category": "DELETED BROWSER TRACE", "artifact": kw, "path": b_name, "hash": "N/A", "timestamp": "Found in raw SQLite"})
                            log(f"FOUND deleted URL trace in {b_name}: {kw}")
                            
                conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
                cur = conn.cursor()
                
                cur.execute("SELECT target_path FROM downloads")
                for row in cur.fetchall():
                    tgt = str(row[0] or "")
                    if tgt.endswith((".lua", ".asi", ".exe", ".dll")) or self._is_cheat(Path(tgt)):
                        findings.append({"severity": "CRITICAL", "category": f"{b_name.upper()} DOWNLOAD", "artifact": Path(tgt).name, "path": tgt, "hash": "Downloaded File", "timestamp": "Browser History"})
                        log(f"FOUND download in {b_name}: {Path(tgt).name}")

                cur.execute("SELECT url, title FROM urls")
                for row in cur.fetchall():
                    url, title = str(row[0]).lower(), str(row[1]).lower()
                    for kw in self.url_keywords:
                        if kw in url or kw in title:
                            findings.append({"severity": "HIGH", "category": f"{b_name.upper()} HISTORY", "artifact": f"Visited: {kw}", "path": str(row[0])[:80], "hash": "N/A", "timestamp": "Browser History"})
                            break
                conn.close()
                tmp_db.unlink(missing_ok=True)
            except Exception:
                pass

        # ==========================================
        # 5. RECENT FILES (LNK)
        # ==========================================
        log("Scanning Recent Files (LNK)...")
        recent_dir = self.roaming / "Microsoft\\Windows\\Recent"
        if recent_dir.exists():
            for f in os.listdir(recent_dir):
                if Path(f).stem.lower() in self.strict_names:
                    findings.append({"severity": "HIGH", "category": "RECENT FILE", "artifact": f, "path": os.path.join(recent_dir, f), "hash": "LNK Shortcut", "timestamp": "Recent Folder"})
                    log(f"FOUND recent shortcut: {f}")

        # ==========================================
        # 6. AMCACHE (Historical Executions)
        # ==========================================
        if HAVE_REGIPY:
            log("Scanning Amcache (Historical Executions)...")
            amcache_path = self.sysroot / "AppCompat\\Programs\\Amcache.hve"
            if amcache_path.exists():
                try:
                    hive = RegistryHive(str(amcache_path))
                    
                    # Check both modern and legacy Amcache paths
                    root = None
                    for path in ["Root\\InventoryApplicationFile", "Root\\File", "Root\\InventoryApplication"]:
                        try:
                            root = hive.get_key(path)
                            break
                        except Exception:
                            continue
                            
                    if root:
                        for sub in root.iter_subkeys():
                            vals = {v.name: v.value for v in sub.iter_values()}
                            path_val = str(vals.get("LowerCaseLongPath", ""))
                            if not path_val:
                                path_val = str(vals.get("Path", ""))
                                
                            fname = Path(path_val).name
                            if path_val and self._is_cheat(path_val):
                                findings.append({"severity": "HIGH", "category": "AMCACHE TRACE", "artifact": fname, "path": path_val, "hash": "Deleted", "timestamp": sub.header.last_modified.isoformat() if sub.header.last_modified else ""})
                                log(f"FOUND historical execution: {fname}")
                except Exception:
                    pass # Silently skip if the hive is locked by Windows
        else:
            log("Amcache skipped (regipy missing).")

        # ==========================================
        # 7. MFT (Deleted Files)
        # ==========================================
        if HAVE_TSK:
            log("Parsing Raw $MFT for deleted executables...")
            try:
                img = pytsk3.Img_Info("\\\\.\\C:")
                fs = pytsk3.FS_Info(img)
                
                # FIXED: Instead of opening the MFT as a directory (which breaks),
                # we loop through every single inode ID on the drive.
                max_inodes = fs.info.last_inum
                log(f"MFT: Scanning {max_inodes} total records for deleted files...")
                
                for inode_id in range(max_inodes):
                    try:
                        # Open the file record at this specific inode
                        file_obj = fs.open_meta(inode=inode_id)
                        if file_obj.info.meta is None:
                            continue
                            
                        # Check if the file is unallocated (deleted)
                        if (file_obj.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC) == 0:
                            name = file_obj.info.name.name.decode("utf-8", "replace") if file_obj.info.name else ""
                            ext = os.path.splitext(name)[1].lower()
                            
                            if ext in target_exts and self._is_cheat(name):
                                findings.append({
                                    "severity": "CRITICAL", 
                                    "category": "DELETED FILE", 
                                    "artifact": name, 
                                    "path": f"MFT Record: {inode_id}", 
                                    "hash": "Deleted", 
                                    "timestamp": "DELETED"
                                })
                                log(f"FOUND deleted file: {name}")
                    except Exception:
                        # Ignore inodes that can't be parsed
                        continue
                        
            except Exception as e:
                log(f"MFT FATAL ERROR: {str(e)}")
        else:
            log(f"MFT skipped (pytsk3 failed to import: {TSK_ERROR})")

        log(f"Scan complete. Total artifacts found: {len(findings)}")
        
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["category"], f["artifact"], f["path"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return {"findings": unique_findings, "logs": logs}

    def open_folder(self, path):
        if "MFT Record" in path or not os.path.exists(path): return
        subprocess.run(["explorer", "/select,", os.path.normpath(path)])

    def get_system_stats(self):
        return {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent}