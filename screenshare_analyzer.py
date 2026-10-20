import os
import psutil
import subprocess
from pathlib import Path

class ScreenshareAnalyzer:
    def __init__(self):
        self.sysroot = Path(os.environ.get("SystemRoot", "C:\\Windows"))
        
        # FIXED: Convert to string FIRST, then lowercase it.
        self.whitelist_paths = [
            str(self.sysroot).lower(),
            os.environ.get("PROGRAMFILES", "C:\\Program Files").lower(),
            os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)").lower(),
            os.environ.get("WINDIR", "C:\\Windows").lower(),
        ]

    def _is_signed(self, filepath):
        if not filepath or not os.path.exists(filepath):
            return False
        try:
            cmd = f'(Get-AuthenticodeSignature "{filepath}").Status'
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return "Valid" in result.stdout
        except Exception:
            return False

    def scan_processes(self):
        findings = []
        suspicious_exts = {".exe", ".dll", ".jar", ".bat", ".py", ".ps1", ".vbs"}
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                exe = proc.info['exe']
                if not exe:
                    continue

                # 1. Check for unsigned executables running from suspicious locations
                if Path(exe).suffix.lower() in suspicious_exts:
                    in_whitelist = any(exe.lower().startswith(wp) for wp in self.whitelist_paths)
                    
                    if not in_whitelist and not self._is_signed(exe):
                        findings.append({
                            "severity": "HIGH",
                            "category": "SCREENSHARE // UNSIGNED EXE",
                            "artifact": proc.info['name'],
                            "path": exe,
                            "hash": "N/A",
                            "timestamp": f"PID: {proc.info['pid']} | User: {proc.info['username']}"
                        })

                # 2. Check for unsigned modules loaded into critical processes
                if proc.info['name'] and proc.info['name'].lower() in ("csrss.exe", "explorer.exe", "svchost.exe"):
                    try:
                        for m in proc.memory_maps():
                            if m.path and m.path.lower().endswith(".dll"):
                                in_whitelist = any(m.path.lower().startswith(wp) for wp in self.whitelist_paths)
                                if not in_whitelist and not self._is_signed(m.path):
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "category": "SCREENSHARE // INJECTION",
                                        "artifact": Path(m.path).name,
                                        "path": m.path,
                                        "hash": "N/A",
                                        "timestamp": f"Loaded in {proc.info['name']} (PID {proc.info['pid']})"
                                    })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def scan_anti_forensics(self):
        findings = []
        
        # 1. Prefetch check
        prefetch_dir = self.sysroot / "Prefetch"
        if prefetch_dir.exists():
            files = list(prefetch_dir.glob("*.pf"))
            if len(files) < 15:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "SCREENSHARE // ANTI-FORENSICS",
                    "artifact": "Prefetch Cleared",
                    "path": str(prefetch_dir),
                    "hash": "N/A",
                    "timestamp": f"Only {len(files)} prefetch files remain."
                })

        # 2. USN Journal check
        try:
            out = subprocess.check_output(["fsutil", "usn", "queryjournal", "C:"], stderr=subprocess.STDOUT, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if "Journal ID: 0x0000000000000000" in out or "not active" in out:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "SCREENSHARE // ANTI-FORENSICS",
                    "artifact": "USN Journal Wiped",
                    "path": "C:\\$Extend\\$UsnJrnl",
                    "hash": "N/A",
                    "timestamp": "Change journal is empty or disabled."
                })
        except Exception:
            pass

        return findings

    def run(self):
        results = []
        results.extend(self.scan_processes())
        results.extend(self.scan_anti_forensics())
        return results