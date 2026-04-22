#!/usr/bin/env python3
"""
rhel-load-analyzer  –  Root Cause Analysis tool for cyclical CPU load spikes on RHEL 8/9.
Uses only standard-library Python 3 + system tools (sysstat/sadf, journalctl, nproc).
Recommended: run as root.

Modes:
  default     analyse historical SA binary files from /var/log/sa/
  --live      deep live investigation of current load spike
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Optional

# ── ANSI colour codes ──────────────────────────────────────────────────────────
R    = "\033[0m"
BOLD = "\033[1m"
RED  = "\033[91m"
YEL  = "\033[93m"
GRN  = "\033[92m"
CYN  = "\033[96m"
BLU  = "\033[94m"
MAG  = "\033[95m"

def c(color: str, text: str) -> str:
    return f"{color}{text}{R}"

# ── Logging helpers ────────────────────────────────────────────────────────────

def die(msg: str) -> None:
    print(c(RED, f"[ERROR] {msg}"), file=sys.stderr)
    sys.exit(1)

def warn(msg: str) -> None:
    print(c(YEL, f"[WARN]  {msg}"))

def info(msg: str) -> None:
    print(c(CYN, f"[INFO]  {msg}"))

# ── Shell utilities ────────────────────────────────────────────────────────────

def run_cmd(cmd: list, timeout: int = 30) -> Optional[str]:
    """Run a command; return stdout string or None on any failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

def get_cpu_count() -> int:
    out = run_cmd(["nproc", "--all"])
    if out:
        try:
            return int(out.strip())
        except ValueError:
            pass
    try:
        with open("/proc/cpuinfo") as f:
            return sum(1 for line in f if line.startswith("processor"))
    except OSError:
        return 4

# ── SA file discovery ──────────────────────────────────────────────────────────

SA_DIR = "/var/log/sa"

def list_sa_files() -> list:
    if not os.path.isdir(SA_DIR):
        die(f"{SA_DIR} not found – is sysstat installed and active?\n"
            "  Fix: dnf install sysstat && systemctl enable --now sysstat")
    return sorted(
        os.path.join(SA_DIR, f)
        for f in os.listdir(SA_DIR)
        if re.match(r"^sa\d+$", f)
    )

def resolve_sa_files(args) -> list:
    if args.sa_file:
        if not os.path.isfile(args.sa_file):
            die(f"SA file not found: {args.sa_file}")
        return [args.sa_file]
    if args.date:
        m = re.match(r"(?:\d{4}-\d{2}-)?(\d{2})$", args.date)
        if not m:
            die("--date must be YYYY-MM-DD or DD (2-digit day of month)")
        path = os.path.join(SA_DIR, f"sa{m.group(1)}")
        if not os.path.isfile(path):
            die(f"No SA file found: {path}")
        return [path]
    files = list_sa_files()
    if not files:
        die(f"No sa* binary files found in {SA_DIR}")
    days = getattr(args, "days", 7)
    return files[-days:]

# ── sadf JSON parsing ──────────────────────────────────────────────────────────

def sadf_json(sa_file: str, sar_flag: str) -> Optional[dict]:
    """Run `sadf -j <file> -- <sar_flag>` and return parsed JSON."""
    cmd = ["sadf", "-j", sa_file, "--", sar_flag]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None

def iter_stats(data: dict):
    """Yield (datetime, ncpu, stat_dict) tuples from any sadf JSON payload."""
    if not data:
        return
    try:
        for host in data["sysstat"]["hosts"]:
            ncpu = host.get("number-of-cpus", 1)
            for stat in host.get("statistics", []):
                ts = stat.get("timestamp", {})
                d, t = ts.get("date", ""), ts.get("time", "")
                if not d or not t:
                    continue
                try:
                    dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                yield dt, ncpu, stat
    except (KeyError, TypeError):
        return

def load_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-q")
    result = {}
    for dt, ncpu, stat in iter_stats(data):
        q = stat.get("queue", {})
        if q:
            result[dt] = {
                "ncpu":     ncpu,
                "ldavg_1":  q.get("ldavg-1", 0.0),
                "ldavg_5":  q.get("ldavg-5", 0.0),
                "ldavg_15": q.get("ldavg-15", 0.0),
                "runq":     q.get("runq-sz", 0),
                "blocked":  q.get("blocked", 0),
            }
    return result

def cpu_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-u")
    result = {}
    for dt, _, stat in iter_stats(data):
        for cpu in stat.get("cpu-load", []):
            if cpu.get("cpu") == "all":
                result[dt] = {
                    "user":   cpu.get("%user",   0.0),
                    "system": cpu.get("%system", 0.0),
                    "iowait": cpu.get("%iowait", 0.0),
                    "steal":  cpu.get("%steal",  0.0),
                    "idle":   cpu.get("%idle",  100.0),
                }
                break
    return result

def mem_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-r")
    result = {}
    for dt, _, stat in iter_stats(data):
        mem = stat.get("memory", {})
        if mem:
            result[dt] = {
                "memused_pct": mem.get("%memused",  0.0),
                "swpused_pct": mem.get("%swpused",  0.0),
                "kbswpused":   mem.get("kbswpused", 0),
            }
    return result

def io_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-b")
    result = {}
    for dt, _, stat in iter_stats(data):
        io = stat.get("io", {})
        if io:
            result[dt] = {
                "tps":     io.get("tps",     0.0),
                "bread_s": io.get("bread/s", 0.0),
                "bwrtn_s": io.get("bwrtn/s", 0.0),
            }
    return result

def paging_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-B")
    result = {}
    for dt, _, stat in iter_stats(data):
        pg = stat.get("paging", {})
        if pg:
            result[dt] = {
                "majflt_s":  pg.get("majflt/s",  0.0),
                "pgpgin_s":  pg.get("pgpgin/s",  0.0),
                "pgpgout_s": pg.get("pgpgout/s", 0.0),
            }
    return result

def ctxsw_metric(sa_file: str) -> dict:
    data = sadf_json(sa_file, "-w")
    result = {}
    for dt, _, stat in iter_stats(data):
        cs = stat.get("process-and-context-switch", {})
        if cs:
            result[dt] = {
                "cswch_s": cs.get("cswch/s", 0.0),
                "proc_s":  cs.get("proc/s",  0.0),
            }
    return result

def closest(d: dict, target: datetime, window: int = 300):
    """Return value from dict whose key is nearest to target within window seconds."""
    best_val, best_diff = None, float("inf")
    for k, v in d.items():
        diff = abs((k - target).total_seconds())
        if diff < best_diff and diff <= window:
            best_val, best_diff = v, diff
    return best_val

# ── Spike detection ────────────────────────────────────────────────────────────

def detect_spikes(load_by_dt: dict, threshold_factor: float = 0.8):
    if not load_by_dt:
        return [], 0.0, 0

    first = next(iter(load_by_dt.values()))
    ncpu = first["ncpu"]
    threshold = ncpu * threshold_factor

    candidates = [
        {"timestamp": dt, **rec}
        for dt, rec in sorted(load_by_dt.items())
        if rec["ldavg_1"] >= threshold
    ]

    merged = []
    for s in candidates:
        if merged and (s["timestamp"] - merged[-1]["timestamp"]).total_seconds() < 300:
            if s["ldavg_1"] > merged[-1]["ldavg_1"]:
                merged[-1] = s
        else:
            merged.append(s)

    return merged, threshold, ncpu

# ── journalctl correlation (historical) ───────────────────────────────────────

_TRIGGER_KEYWORDS = [
    "Started", "Stopped", "oom-kill", "oom_kill", "OOM",
    "cron", "backup", "rsync", "dnf", "yum", "ansible",
    "restarted", "activated", "deactivated",
]

def journal_around(dt: datetime, minutes: int = 3) -> list:
    since = (dt - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    until = (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    lines: list = []
    out = run_cmd([
        "journalctl", "--since", since, "--until", until,
        "--no-pager", "-o", "short-iso", "-p", "0..4", "--lines", "15",
    ], timeout=15)
    if out:
        lines += [l for l in out.splitlines() if l and "No entries" not in l]
    out2 = run_cmd([
        "journalctl", "--since", since, "--until", until,
        "--no-pager", "-o", "short-iso", "--lines", "25",
        "--grep", "|".join(_TRIGGER_KEYWORDS),
    ], timeout=15)
    if out2:
        for l in out2.splitlines():
            if l and "No entries" not in l and l not in lines:
                lines.append(l)
    return lines[:25]

def extract_trigger(journal_lines: list) -> str:
    for line in journal_lines:
        for kw in _TRIGGER_KEYWORDS:
            if kw.lower() in line.lower():
                msg = line.split(": ", 1)[-1] if ": " in line else line
                return msg[:28].strip()
    return "-"

# ── Spike classification (historical) ─────────────────────────────────────────

_FACTOR_COLOR = {
    "IO-Bound":   BLU,
    "CPU-User":   RED,
    "CPU-Kernel": MAG,
    "MEM-Swap":   YEL,
    "MEM-Paging": YEL,
    "Unknown":    R,
}

def classify(cpu: Optional[dict], mem: Optional[dict],
             io: Optional[dict], paging: Optional[dict]) -> tuple:
    scores = {}
    if cpu:
        iowait = cpu.get("iowait", 0)
        user   = cpu.get("user",   0)
        system = cpu.get("system", 0)
        if iowait > 15:
            scores["IO-Bound"]   = (iowait, f"iowait={iowait:.1f}%")
        if user > 40:
            scores["CPU-User"]   = (user,   f"user={user:.1f}%")
        if system > 25:
            scores["CPU-Kernel"] = (system, f"sys={system:.1f}%")
    if mem:
        swp = mem.get("swpused_pct", 0)
        if swp > 5:
            scores["MEM-Swap"]   = (swp,    f"swap={swp:.1f}%")
    if paging:
        mf = paging.get("majflt_s", 0)
        if mf > 50:
            scores["MEM-Paging"] = (mf,     f"majflt={mf:.0f}/s")
    if not scores:
        return "Unknown", "-"
    dominant = max(scores, key=lambda k: scores[k][0])
    detail = " | ".join(v[1] for v in scores.values())
    return dominant, detail

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE ANALYSIS MODE
# ══════════════════════════════════════════════════════════════════════════════

def live_loadavg() -> dict:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        runq, total = parts[3].split("/")
        return {
            "la1":   float(parts[0]),
            "la5":   float(parts[1]),
            "la15":  float(parts[2]),
            "runq":  int(runq),
            "total": int(total),
        }
    except (OSError, ValueError, IndexError):
        return {}

def live_meminfo() -> dict:
    result = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                m = re.match(r"^(\w+):\s+(\d+)", line)
                if m:
                    result[m.group(1)] = int(m.group(2))  # kB
    except OSError:
        pass
    return result

def live_top_procs(n: int = 15) -> list:
    out = run_cmd([
        "ps", "-eo", "pid,user,stat,pcpu,pmem,vsz,rss,comm",
        "--sort=-%cpu", "--no-headers",
    ])
    if not out:
        return []
    result = []
    for line in out.splitlines()[:n]:
        parts = line.split(None, 7)
        if len(parts) >= 8:
            try:
                result.append({
                    "pid":  parts[0],
                    "user": parts[1],
                    "stat": parts[2],
                    "cpu":  float(parts[3]),
                    "mem":  float(parts[4]),
                    "vsz":  int(parts[5]),
                    "rss":  int(parts[6]),
                    "comm": parts[7].strip(),
                })
            except ValueError:
                continue
    return result

def live_dstate_procs() -> list:
    """
    Find all D-state (uninterruptible sleep) processes.
    These processes directly inflate load average without consuming CPU –
    the most common silent culprit that tools like 'top' make hard to spot.
    """
    out = run_cmd([
        "ps", "-eo", "pid,user,stat,pcpu,pmem,comm,wchan:40",
        "--no-headers",
    ])
    if not out:
        return []
    result = []
    for line in out.splitlines():
        parts = line.split(None, 6)
        if len(parts) >= 3 and parts[2].startswith("D"):
            result.append({
                "pid":   parts[0],
                "user":  parts[1],
                "stat":  parts[2],
                "cpu":   parts[3] if len(parts) > 3 else "0.0",
                "mem":   parts[4] if len(parts) > 4 else "0.0",
                "comm":  parts[5] if len(parts) > 5 else "?",
                "wchan": parts[6].strip() if len(parts) > 6 else "?",
            })
    return result

def live_zombie_procs() -> list:
    out = run_cmd(["ps", "-eo", "pid,user,stat,ppid,comm", "--no-headers"])
    if not out:
        return []
    return [
        line.strip() for line in out.splitlines()
        if len(line.split()) >= 3 and line.split()[2].startswith("Z")
    ]

def live_proc_details(pid: str) -> dict:
    """Read /proc/<pid>/ for cmdline, I/O stats, and fd count."""
    details: dict = {}
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            details["cmdline"] = f.read().replace("\x00", " ").strip()[:100]
    except OSError:
        details["cmdline"] = ""
    try:
        with open(f"/proc/{pid}/io") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    details[k.strip()] = int(v.strip())
    except OSError:
        pass
    try:
        details["fd_count"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        details["fd_count"] = 0
    return details

def classify_wchan(wchan: str) -> str:
    """Translate a kernel wait channel into human-readable meaning."""
    w = wchan.lower()
    if any(x in w for x in ["nfs", "rpc_wait", "nfs4"]):
        return "NFS / network storage"
    if any(x in w for x in ["xfs_", "ext4", "btrfs", "jbd2", "f2fs"]):
        return "filesystem I/O"
    if any(x in w for x in ["blk_", "bio_", "scsi", "nvme", "ahci", "ata_"]):
        return "block device I/O"
    if any(x in w for x in ["mutex", "rwsem", "down_", "semaphore", "lock"]):
        return "kernel lock / mutex contention"
    if any(x in w for x in ["pipe_", "do_read", "do_write", "sock_", "tcp_", "inet_"]):
        return "network / IPC / pipe wait"
    if any(x in w for x in ["wait_for_completion", "complete_all"]):
        return "async kernel operation"
    if any(x in w for x in ["do_nanosleep", "schedule_timeout", "hrtimer"]):
        return "intentional sleep (normal)"
    if wchan in ("0", "-", ""):
        return "running / no wait"
    return f"kernel: {wchan}"

def parse_vmstat_line(line: str) -> Optional[dict]:
    parts = line.split()
    if len(parts) < 17 or not parts[0].isdigit():
        return None
    try:
        return {
            "r":  int(parts[0]),
            "b":  int(parts[1]),
            "swpd": int(parts[2]),
            "free": int(parts[3]),
            "si": int(parts[6]),
            "so": int(parts[7]),
            "bi": int(parts[8]),
            "bo": int(parts[9]),
            "in": int(parts[10]),
            "cs": int(parts[11]),
            "us": int(parts[12]),
            "sy": int(parts[13]),
            "id": int(parts[14]),
            "wa": int(parts[15]),
            "st": int(parts[16]),
        }
    except (ValueError, IndexError):
        return None

def live_vmstat(samples: int = 10) -> list:
    """
    Run vmstat 1 N+1 and discard the first line (cumulative since boot).
    Returns per-second snapshots suitable for averaging.
    """
    info(f"Sampling vmstat ({samples}s) ...")
    out = run_cmd(["vmstat", "1", str(samples + 1)], timeout=samples + 20)
    if not out:
        return []
    data_lines = [l for l in out.splitlines() if l.strip() and l.strip()[0].isdigit()]
    records = []
    for line in data_lines[1:]:   # skip first data row (cumulative avg since boot)
        r = parse_vmstat_line(line)
        if r:
            records.append(r)
    return records

def live_iostat(samples: int = 5) -> list:
    """
    Run iostat -xz 1 N and return the last snapshot (most recent interval).
    -x = extended stats  -z = hide idle devices
    """
    info(f"Sampling iostat ({samples}s) ...")
    out = run_cmd(["iostat", "-xz", "1", str(samples)], timeout=samples + 15)
    if not out:
        return []

    # Split output into per-interval chunks, take the last one that has a Device section
    chunks = re.split(r"\n\s*\n", out)
    for chunk in reversed(chunks):
        if "Device" not in chunk:
            continue
        devices = []
        headers: list = []
        for line in chunk.splitlines():
            line = line.strip()
            if line.startswith("Device"):
                headers = line.split()
                continue
            if not headers or not line:
                continue
            parts = line.split()
            if not parts or parts[0][0].isdigit():
                continue
            dev: dict = {"device": parts[0]}
            for i, h in enumerate(headers[1:], 1):
                try:
                    dev[h] = float(parts[i]) if i < len(parts) else 0.0
                except ValueError:
                    dev[h] = 0.0
            devices.append(dev)
        if devices:
            return devices
    return []

def live_journal_recent(minutes: int = 10) -> list:
    since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    lines: list = []
    out = run_cmd([
        "journalctl", "--since", since, "--no-pager",
        "-o", "short-iso", "-p", "0..4", "--lines", "25",
    ], timeout=10)
    if out:
        lines += [l for l in out.splitlines() if l and "No entries" not in l]
    out2 = run_cmd([
        "journalctl", "--since", since, "--no-pager",
        "-o", "short-iso", "--lines", "40",
        "--grep", "Started|Stopped|oom-kill|oom_kill|OOM|cron|backup|rsync|dnf|yum",
    ], timeout=10)
    if out2:
        for l in out2.splitlines():
            if l and "No entries" not in l and l not in lines:
                lines.append(l)
    return lines[:40]

def live_recent_timers() -> list:
    """Return systemd timers that triggered within the last 30 minutes."""
    out = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"], timeout=10)
    if not out:
        return []
    result = []
    for line in out.splitlines():
        m = re.search(r"(\d+) (min|s) ago", line)
        if m:
            val, unit = int(m.group(1)), m.group(2)
            secs_ago = val if unit == "s" else val * 60
            if secs_ago <= 1800:
                result.append(line.strip())
    return result[:10]

def live_build_verdict(ncpu: int, la: dict, dstate: list, vmstat_data: list,
                       iostat_data: list, meminfo: dict,
                       journal: list, timers: list) -> dict:
    """
    Synthesise all collected data into a single weighted verdict.
    Returns dict with primary cause, evidence list, suspects, and actions.
    """
    scores: dict  = {}
    evidence: list = []
    suspects: list = []

    la1 = la.get("la1", 0.0)

    # ── D-state processes ──────────────────────────────────────────────────────
    # Each D-state process contributes exactly 1.0 to load average.
    # This is the single most reliable indicator of I/O or lock stalls.
    if dstate:
        top_wchan = dstate[0]["wchan"]
        meaning   = classify_wchan(top_wchan)
        scores["D-state / I-O stall"] = len(dstate) * 20
        evidence.append(
            f"{len(dstate)} process(es) in D-state (uninterruptible sleep) "
            f"– each adds +1.0 to load average. wchan: {meaning}"
        )
        for p in dstate[:4]:
            suspects.append(
                f"PID {p['pid']} ({p['comm']}) "
                f"stat={p['stat']} wchan={p['wchan']} → {classify_wchan(p['wchan'])}"
            )

    # ── vmstat analysis ────────────────────────────────────────────────────────
    if vmstat_data:
        def avg(key: str) -> float:
            return sum(s.get(key, 0) for s in vmstat_data) / len(vmstat_data)

        avg_r  = avg("r")
        avg_b  = avg("b")
        avg_wa = avg("wa")
        avg_si = avg("si")
        avg_so = avg("so")
        avg_cs = avg("cs")
        avg_us = avg("us")
        avg_sy = avg("sy")

        if avg_r > ncpu:
            scores["CPU Saturation"] = avg_r * 8
            evidence.append(
                f"Run queue avg={avg_r:.1f} exceeds CPU count ({ncpu}) "
                f"– CPU is the bottleneck"
            )
        if avg_b > 1:
            scores["I/O Blocking"] = max(scores.get("I/O Blocking", 0), avg_b * 15)
            evidence.append(
                f"Blocked processes avg={avg_b:.1f} "
                f"(waiting on I/O, not CPU)"
            )
        if avg_wa > 10:
            scores["I/O Wait"] = max(scores.get("I/O Wait", 0), avg_wa * 3)
            evidence.append(f"iowait avg={avg_wa:.1f}% – CPU idle waiting on disk")
        if avg_si + avg_so > 2:
            scores["Memory Pressure"] = (avg_si + avg_so) * 12
            evidence.append(
                f"Active swapping: si={avg_si:.0f} so={avg_so:.0f} pages/s "
                f"– RAM exhausted"
            )
        if avg_cs > 100_000:
            scores["Context Switch Storm"] = avg_cs / 5000
            evidence.append(
                f"Context switches avg={avg_cs:,.0f}/s "
                f"– likely lock contention or many short-lived threads"
            )
        if avg_us > 60:
            scores["CPU Saturation"] = max(scores.get("CPU Saturation", 0), avg_us)
            evidence.append(f"User-space CPU avg={avg_us:.1f}% – application is CPU-bound")
        if avg_sy > 30:
            scores["Kernel CPU"] = avg_sy * 2
            evidence.append(
                f"Kernel CPU avg={avg_sy:.1f}% – syscall/IRQ overhead "
                f"(network flood, disk interrupts, or bad driver?)"
            )

    # ── iostat analysis ────────────────────────────────────────────────────────
    saturated = []
    for dev in iostat_data:
        util   = dev.get("%util", 0)
        await_ = dev.get("await", dev.get("aqu-sz", 0))
        if util > 70:
            saturated.append(f"{dev['device']} util={util:.0f}% await={await_:.1f}ms")
    if saturated:
        scores["Disk Saturation"] = max(scores.get("Disk Saturation", 0), 80)
        evidence.append(f"Saturated disk(s): {', '.join(saturated)}")
        suspects.append(f"Disk bottleneck – investigate: iostat -xz 1 10 | grep -v ' 0.00'")

    # ── memory analysis ────────────────────────────────────────────────────────
    if meminfo:
        total  = meminfo.get("MemTotal", 1)
        avail  = meminfo.get("MemAvailable", total)
        stot   = meminfo.get("SwapTotal", 0)
        sfree  = meminfo.get("SwapFree", stot)
        sused  = stot - sfree
        avail_pct = avail / total * 100

        if avail_pct < 10:
            scores["Memory Exhaustion"] = (10 - avail_pct) * 10
            evidence.append(
                f"Only {avail_pct:.1f}% RAM available "
                f"({avail // 1024} MB free of {total // 1024} MB)"
            )
        if stot > 0 and sused > stot * 0.25:
            scores["Memory Pressure"] = max(
                scores.get("Memory Pressure", 0), sused / stot * 80
            )
            evidence.append(
                f"Swap usage: {sused // 1024} MB / {stot // 1024} MB "
                f"({sused / stot * 100:.0f}%)"
            )

    # ── OOM killer ────────────────────────────────────────────────────────────
    oom_lines = [l for l in journal if "oom" in l.lower() or "killed process" in l.lower()]
    if oom_lines:
        scores["OOM Killer"] = 95
        evidence.append(f"OOM killer triggered: {len(oom_lines)} event(s) in last 10 min")
        for l in oom_lines[:2]:
            suspects.append("OOM: " + l.split(": ", 1)[-1][:70])

    # ── scheduled jobs ────────────────────────────────────────────────────────
    if timers:
        evidence.append(
            f"{len(timers)} systemd timer(s) fired recently – "
            f"may be the trigger"
        )
        for t in timers[:2]:
            suspects.append(f"Timer: {t[:80]}")

    # ── determine primary cause ────────────────────────────────────────────────
    if not scores:
        primary = "Undetermined"
        summary = (
            "Load is elevated but no single bottleneck identified. "
            "Possible causes: short-lived forks flooding the scheduler, "
            "NFS mount stall, or a kernel bug. "
            "Run: strace -p <top_pid> and perf top -a"
        )
    else:
        primary = max(scores, key=lambda k: scores[k])
        summary = None

    return {
        "primary":  primary,
        "scores":   scores,
        "evidence": evidence,
        "suspects": suspects,
        "summary":  summary,
    }

def run_live_analysis(threshold_factor: float = 0.8) -> None:
    """
    Deep live investigation of current load.
    Mimics what a senior RHEL engineer does when paged for high load.
    """
    now  = datetime.now()
    ncpu = get_cpu_count()
    threshold = ncpu * threshold_factor

    print_header(
        f"rhel-load-analyzer  ·  LIVE ANALYSIS  –  {now.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ── 1. Load triage ────────────────────────────────────────────────────────
    la = live_loadavg()
    if not la:
        die("Cannot read /proc/loadavg")

    la1   = la["la1"]
    ratio = la1 / threshold if threshold > 0 else 0

    if la1 >= threshold * 2.0:
        status_str = c(RED,  f"CRITICAL  ({ratio:.1f}× threshold)")
    elif la1 >= threshold:
        status_str = c(YEL,  f"ELEVATED  ({ratio:.1f}× threshold)")
    else:
        status_str = c(GRN,  f"NORMAL  ({ratio:.1f}× threshold)")

    print(f"\n  Load average  : {BOLD}{la1:.2f}  {la.get('la5',0):.2f}  {la.get('la15',0):.2f}{R}"
          f"  (1m / 5m / 15m)")
    print(f"  CPU cores     : {BOLD}{ncpu}{R}")
    print(f"  Threshold     : {BOLD}{threshold:.2f}{R}  ({threshold_factor} × {ncpu})")
    print(f"  Run queue now : {la.get('runq', '?')} processes")
    print(f"  Status        : {status_str}")

    # ── 2. Process snapshot ───────────────────────────────────────────────────
    info("Collecting process snapshot ...")
    top_procs = live_top_procs(15)
    dstate    = live_dstate_procs()
    zombies   = live_zombie_procs()

    print_section("TOP PROCESSES BY CPU")
    print(f"\n  {'PID':<8} {'USER':<12} {'STAT':<6} {'%CPU':>6} {'%MEM':>6} "
          f"{'RSS MB':>7}  {'COMMAND'}")
    print("  " + "─" * 70)
    for p in top_procs[:12]:
        rss_mb   = p["rss"] // 1024
        stat_col = RED if p["stat"].startswith("D") \
              else YEL if p["stat"].startswith(("R", "Z")) \
              else R
        print(f"  {p['pid']:<8} {p['user']:<12} "
              f"{stat_col}{p['stat']:<6}{R} "
              f"{p['cpu']:>6.1f} {p['mem']:>6.1f} "
              f"{rss_mb:>7}  {p['comm'][:35]}")

    if zombies:
        print(f"\n  {YEL}Zombie processes ({len(zombies)}) – parent may be leaking:{R}")
        for z in zombies[:5]:
            print(f"    {z}")

    # ── 3. D-state investigation ──────────────────────────────────────────────
    print_section(
        f"D-STATE PROCESSES  (uninterruptible sleep = direct load contribution)"
    )

    if not dstate:
        print(f"\n  {GRN}None.  No processes stuck in uninterruptible sleep.{R}")
    else:
        print(f"\n  {RED}{BOLD}! {len(dstate)} process(es) in D-state{R}"
              f"  – each one adds +1.0 to load average regardless of CPU usage.\n")
        print(f"  {'PID':<8} {'USER':<10} {'%CPU':>5} {'COMMAND':<22} "
              f"{'WCHAN':<32} {'MEANING'}")
        print("  " + "─" * 95)
        for p in dstate:
            meaning  = classify_wchan(p["wchan"])
            details  = live_proc_details(p["pid"])
            rb       = details.get("read_bytes",  0) // 1048576
            wb       = details.get("write_bytes", 0) // 1048576
            fds      = details.get("fd_count", "?")
            print(f"  {p['pid']:<8} {p['user']:<10} {p['cpu']:>5} "
                  f"{p['comm']:<22} {p['wchan']:<32} {CYN}{meaning}{R}")
            if details.get("cmdline"):
                print(f"           {BLU}cmd:{R} {details['cmdline'][:85]}")
            if rb or wb:
                print(f"           {BLU}I/O:{R} "
                      f"total read={rb} MB  write={wb} MB  open fds={fds}")

    # ── 4. vmstat ─────────────────────────────────────────────────────────────
    vmstat_data = live_vmstat(10)

    print_section("VMSTAT  (10-second sample, 1s intervals)")

    if vmstat_data:
        def avg(key: str) -> float:
            return sum(s.get(key, 0) for s in vmstat_data) / len(vmstat_data)
        def vmn(key: str) -> float:
            return min(s.get(key, 0) for s in vmstat_data)
        def vmx(key: str) -> float:
            return max(s.get(key, 0) for s in vmstat_data)

        print(f"\n  {'Metric':<22} {'Min':>7} {'Avg':>7} {'Max':>7}   Interpretation")
        print("  " + "─" * 70)

        def row(label: str, key: str, warn: float, crit: float, interp: str) -> None:
            mn, av, mx = vmn(key), avg(key), vmx(key)
            col = RED if av >= crit else (YEL if av >= warn else GRN)
            print(f"  {label:<22} {mn:>7.0f} {col}{av:>7.0f}{R} {mx:>7.0f}   {interp}")

        row("run queue (r)",      "r",  ncpu,    ncpu * 2,
            f"{'!! SATURATED' if avg('r')>ncpu else 'OK'}  (ncpu={ncpu})")
        row("blocked (b)",        "b",  2,       5,
            f"{'!! I/O blocked processes' if avg('b')>1 else 'none blocked'}")
        row("iowait %",           "wa", 10,      25,
            f"{'!! HIGH – disk bottleneck' if avg('wa')>10 else 'acceptable'}")
        row("user cpu %",         "us", 60,      85,
            f"{'application heavy' if avg('us')>60 else 'normal'}")
        row("sys cpu %",          "sy", 20,      40,
            f"{'kernel overhead' if avg('sy')>20 else 'normal'}")
        row("idle %",             "id", 0,       0,
            f"{'headroom available' if avg('id')>30 else 'very tight'}")
        row("swap-in  (si pg/s)", "si", 1,       100,
            f"{'!! RAM exhausted' if avg('si')>1 else 'no swapping'}")
        row("swap-out (so pg/s)", "so", 1,       100,
            f"{'!! RAM exhausted' if avg('so')>1 else 'no swapping'}")
        row("interrupts/s (in)",  "in", 50000,   200000,
            f"{'high IRQ rate' if avg('in')>50000 else 'normal'}")
        row("ctx-switches/s (cs)","cs", 100000,  300000,
            f"{'!! contention' if avg('cs')>100000 else 'normal'}")
    else:
        print(f"\n  {YEL}vmstat unavailable{R}")

    # ── 5. Disk I/O ───────────────────────────────────────────────────────────
    iostat_data = live_iostat(5)

    print_section("DISK I/O  (iostat -xz, 5-second sample)")

    if iostat_data:
        print(f"\n  {'Device':<14} {'%util':>7} {'await ms':>10} "
              f"{'r/s':>7} {'w/s':>7} {'rMB/s':>7} {'wMB/s':>7}   Status")
        print("  " + "─" * 78)
        for dev in sorted(iostat_data, key=lambda d: d.get("%util", 0), reverse=True):
            util   = dev.get("%util", 0)
            await_ = dev.get("await", dev.get("aqu-sz", 0))
            rs     = dev.get("r/s", 0)
            ws     = dev.get("w/s", 0)
            rmb    = dev.get("rMB/s", dev.get("rkB/s", 0) / 1024)
            wmb    = dev.get("wMB/s", dev.get("wkB/s", 0) / 1024)
            col    = RED if util > 80 else (YEL if util > 50 else GRN)
            status = "!! SATURATED" if util > 80 else ("BUSY" if util > 50 else "ok")
            print(f"  {dev['device']:<14} {col}{util:>7.1f}{R} {await_:>10.1f} "
                  f"{rs:>7.0f} {ws:>7.0f} {rmb:>7.1f} {wmb:>7.1f}   {col}{status}{R}")
    else:
        print(f"\n  {YEL}iostat unavailable (install sysstat){R}")

    # ── 6. Memory ─────────────────────────────────────────────────────────────
    meminfo = live_meminfo()

    print_section("MEMORY")

    if meminfo:
        total    = meminfo.get("MemTotal",     1)
        avail    = meminfo.get("MemAvailable", total)
        cached   = meminfo.get("Cached", 0) + meminfo.get("Buffers", 0)
        dirty    = meminfo.get("Dirty",  0)
        stot     = meminfo.get("SwapTotal", 0)
        sfree    = meminfo.get("SwapFree",  stot)
        sused    = stot - sfree
        avail_pct = avail / total * 100

        mem_col  = RED if avail_pct < 10 else (YEL if avail_pct < 20 else GRN)
        swap_col = RED if (stot > 0 and sused > stot * 0.25) \
              else (YEL if sused > 0 else GRN)
        dirty_col = YEL if dirty > 1_000_000 else GRN

        print(f"\n  RAM   total={total//1024:,} MB  "
              f"avail={mem_col}{avail//1024:,} MB ({avail_pct:.1f}%){R}  "
              f"cache+buf={cached//1024:,} MB  "
              f"dirty={dirty_col}{dirty//1024:,} MB{R}")

        if stot > 0:
            print(f"  Swap  total={stot//1024:,} MB  "
                  f"used={swap_col}{sused//1024:,} MB ({sused/stot*100:.1f}%){R}  "
                  f"free={sfree//1024:,} MB")
        else:
            print(f"  Swap  {YEL}not configured{R}")

        # OOM risk score
        if avail_pct < 5:
            print(f"\n  {RED}{BOLD}!! OOM risk is HIGH – less than 5% RAM available{R}")
            print(f"  Check: journalctl -k --grep='oom_kill' | tail -10")
    else:
        print(f"\n  {YEL}Cannot read /proc/meminfo{R}")

    # ── 7. Journal ────────────────────────────────────────────────────────────
    info("Querying journalctl (last 10 min) ...")
    journal = live_journal_recent(10)

    print_section("RECENT JOURNAL  (last 10 min: errors + service events)")

    if journal:
        for line in journal[:20]:
            hl = RED if any(x in line.lower() for x in ["error", "fail", "oom", "kill", "crit"]) \
                 else YEL if any(x in line.lower() for x in ["warn", "started", "stopped"]) \
                 else R
            print(f"  {hl}{line}{R}")
    else:
        print(f"\n  {GRN}No errors or notable events found.{R}")

    # ── 8. Scheduled tasks ────────────────────────────────────────────────────
    timers = live_recent_timers()

    if timers:
        print(f"\n  {BOLD}Systemd timers fired recently (possible trigger):{R}")
        for t in timers:
            print(f"  {YEL}▸{R} {t}")
    else:
        print(f"\n  {GRN}No systemd timers fired in the last 30 minutes.{R}")

    # ── 9. Verdict ────────────────────────────────────────────────────────────
    verdict = live_build_verdict(
        ncpu, la, dstate, vmstat_data, iostat_data, meminfo, journal, timers
    )

    print_section("VERDICT")

    primary = verdict["primary"]
    vcol    = RED if primary not in ("Undetermined", "Normal") else YEL

    print(f"\n  {BOLD}Primary cause : {vcol}{primary}{R}")

    if verdict["scores"]:
        print(f"\n  {BOLD}Confidence scores:{R}")
        for cause, score in sorted(verdict["scores"].items(),
                                   key=lambda x: x[1], reverse=True):
            bar = "█" * min(int(score / 5), 20)
            print(f"    {cause:<30} {score:>5.0f}  {YEL}{bar}{R}")

    if verdict["evidence"]:
        print(f"\n  {BOLD}Evidence:{R}")
        for e in verdict["evidence"]:
            print(f"    {RED}●{R} {e}")

    if verdict["suspects"]:
        print(f"\n  {BOLD}Suspects:{R}")
        for s in verdict["suspects"]:
            print(f"    {YEL}▸{R} {s}")

    if verdict["summary"]:
        print(f"\n  {YEL}{verdict['summary']}{R}")

    # ── 10. Immediate actions ─────────────────────────────────────────────────
    recs_map = {
        "D-state / I-O stall":   _RECS["IO-Bound"],
        "I/O Blocking":          _RECS["IO-Bound"],
        "I/O Wait":              _RECS["IO-Bound"],
        "Disk Saturation":       _RECS["IO-Bound"],
        "CPU Saturation":        _RECS["CPU-User"],
        "Kernel CPU":            _RECS["CPU-Kernel"],
        "Context Switch Storm":  _RECS["CPU-Kernel"],
        "Memory Pressure":       _RECS["MEM-Swap"],
        "Memory Exhaustion":     _RECS["MEM-Swap"],
        "OOM Killer":            _RECS["MEM-Swap"],
    }
    recs = recs_map.get(primary, _RECS["Unknown"])

    print(f"\n  {BOLD}Immediate actions:{R}")
    for rec in recs:
        print(f"    {GRN}▸{R}  {rec}")

    print(f"\n{BOLD}{BLU}{'═' * 78}{R}\n")

# ══════════════════════════════════════════════════════════════════════════════
#  RECOMMENDATIONS (shared between live and historical modes)
# ══════════════════════════════════════════════════════════════════════════════

_RECS: dict = {
    "IO-Bound": [
        "tuned-adm profile throughput-performance",
        "echo mq-deadline > /sys/block/<dev>/queue/scheduler",
        "sysctl -w vm.dirty_ratio=10 vm.dirty_background_ratio=3",
        "iostat -xz 1 10               # identify saturated device",
        "lsof -p <pid>                  # open files for D-state process",
        "cat /proc/<pid>/wchan          # exact kernel wait function",
    ],
    "CPU-User": [
        "renice +10 -p <pid>",
        "systemctl set-property <unit>.service CPUQuota=50%",
        "systemctl list-timers --all    # coinciding scheduled jobs?",
        "perf top -p <pid>             # profile hot code paths",
    ],
    "CPU-Kernel": [
        "tuned-adm profile latency-performance",
        "sysctl -w kernel.sched_min_granularity_ns=10000000",
        "cat /proc/interrupts | sort -k2 -rn | head",
        "perf record -ag -- sleep 10; perf report",
    ],
    "MEM-Swap": [
        "sysctl -w vm.swappiness=10",
        "smem -r -s rss | head -15      # top RSS consumers",
        "journalctl -k --grep='oom_kill' --since=-1h",
        "systemctl set-property <unit>.service MemoryMax=2G",
    ],
    "MEM-Paging": [
        "sysctl -w vm.min_free_kbytes=131072",
        "echo never > /sys/kernel/mm/transparent_hugepage/enabled",
        "numactl --hardware && numastat  # NUMA imbalance?",
    ],
    "Unknown": [
        "vmstat 1 20",
        "sar -A -f /var/log/sa/saXX | less",
        "strace -c -p <pid>             # syscall breakdown",
        "perf top -a                    # system-wide hotspot",
    ],
}

def recommendations(dominant: str) -> list:
    return _RECS.get(dominant, _RECS["Unknown"])

# ── Report rendering ───────────────────────────────────────────────────────────

def print_header(title: str) -> None:
    bar = "═" * 78
    print(f"\n{BOLD}{BLU}{bar}{R}")
    print(f"{BOLD}{BLU}  {title}{R}")
    print(f"{BOLD}{BLU}{bar}{R}")

def print_section(title: str) -> None:
    pad = "─" * max(0, 74 - len(title))
    print(f"\n{BOLD}{CYN}── {title} {pad}{R}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rhel-load-analyzer",
        description="Root Cause Analysis for CPU load spikes on RHEL 8/9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 rhel-load-analyzer.py --live
  sudo python3 rhel-load-analyzer.py --live --threshold 0.6
  sudo python3 rhel-load-analyzer.py --days 7
  sudo python3 rhel-load-analyzer.py --date 21
  sudo python3 rhel-load-analyzer.py --sa-file /var/log/sa/sa21
  sudo python3 rhel-load-analyzer.py --no-color > report.txt
        """,
    )
    parser.add_argument("--live",      action="store_true",
                        help="Deep live investigation of current load (no SA files needed)")
    parser.add_argument("--sa-file",   metavar="FILE",
                        help="Path to a specific sa binary file (e.g. /var/log/sa/sa21)")
    parser.add_argument("--date",      metavar="DD",
                        help="Day number or YYYY-MM-DD to analyse (e.g. 21 or 2024-04-21)")
    parser.add_argument("--days",      type=int, default=7, metavar="N",
                        help="How many most recent SA files to analyse  [default: 7]")
    parser.add_argument("--threshold", type=float, default=0.8,
                        help="Load threshold multiplier  [default: 0.8 × nCPU]")
    parser.add_argument("--no-color",  action="store_true",
                        help="Disable ANSI colour output")
    args = parser.parse_args()

    if args.no_color:
        global R, BOLD, RED, YEL, GRN, CYN, BLU, MAG
        R = BOLD = RED = YEL = GRN = CYN = BLU = MAG = ""

    if os.geteuid() != 0:
        warn("Not running as root – journalctl and some /proc data may be restricted.")

    # ── Live mode ──────────────────────────────────────────────────────────────
    if args.live:
        run_live_analysis(args.threshold)
        return

    # ── Historical SA file mode ────────────────────────────────────────────────
    if not run_cmd(["sadf", "-V"], timeout=5):
        die("'sadf' not found. Install sysstat:\n"
            "  dnf install sysstat && systemctl enable --now sysstat")

    sa_files = resolve_sa_files(args)
    info(f"Analysing {len(sa_files)} SA file(s): {', '.join(sa_files)}")

    all_load    = {}
    all_cpu     = {}
    all_mem     = {}
    all_io      = {}
    all_paging  = {}
    all_ctxsw   = {}

    for sa_file in sa_files:
        info(f"Loading metrics from {os.path.basename(sa_file)} ...")
        all_load.update(load_metric(sa_file))
        all_cpu.update(cpu_metric(sa_file))
        all_mem.update(mem_metric(sa_file))
        all_io.update(io_metric(sa_file))
        all_paging.update(paging_metric(sa_file))
        all_ctxsw.update(ctxsw_metric(sa_file))

    if not all_load:
        die("No load-average data found. "
            "Ensure sysstat is collecting: systemctl status sysstat")

    spikes, threshold, ncpu = detect_spikes(all_load, args.threshold)

    print_header("rhel-load-analyzer  ·  Load Spike Root Cause Analysis")

    dts = sorted(all_load.keys())
    print(f"\n  Host CPUs   : {BOLD}{ncpu}{R}")
    print(f"  Threshold   : {BOLD}{threshold:.2f}{R}  ({args.threshold} × {ncpu} cores)")
    print(f"  SA files    : {len(sa_files)}")
    print(f"  Time range  : {dts[0].strftime('%Y-%m-%d %H:%M')} "
          f"→ {dts[-1].strftime('%Y-%m-%d %H:%M')}")
    spike_label = c(RED if spikes else GRN, str(len(spikes)))
    print(f"  Spikes found: {BOLD}{spike_label}{R}")

    if not spikes:
        print(f"\n{GRN}  No load spikes above threshold {threshold:.2f} detected.{R}\n")
        return

    factor_counts: dict = {}

    for spike in spikes:
        dt  = spike["timestamp"]
        cpu = closest(all_cpu,    dt)
        mem = closest(all_mem,    dt)
        io  = closest(all_io,     dt)
        pag = closest(all_paging, dt)
        csw = closest(all_ctxsw,  dt)

        factor, detail = classify(cpu, mem, io, pag)
        factor_counts[factor] = factor_counts.get(factor, 0) + 1

        spike["_factor"]  = factor
        spike["_detail"]  = detail
        spike["_cpu"]     = cpu
        spike["_mem"]     = mem
        spike["_io"]      = io
        spike["_csw"]     = csw
        spike["_journal"] = journal_around(dt)

    print_section("CORRELATION TABLE")

    col_w = [21, 6, 6, 6, 4, 10, 22, 26]
    hdrs  = ["Timestamp", "Ld-1m", "Ld-5m", "Ld-15", "blkd",
             "Dominant", "Key Metrics", "Suspected Trigger"]
    hline = "  ".join(h.ljust(w) for h, w in zip(hdrs, col_w))
    print(f"\n  {BOLD}{hline}{R}")
    print("  " + "─" * (sum(col_w) + 2 * (len(col_w) - 1)))

    for spike in spikes:
        dt      = spike["timestamp"]
        factor  = spike["_factor"]
        detail  = spike["_detail"]
        trigger = extract_trigger(spike["_journal"])
        fc      = _FACTOR_COLOR.get(factor, R)
        ld_col  = RED if spike["ldavg_1"] >= threshold * 1.5 else YEL

        row = [
            dt.strftime("%Y-%m-%d %H:%M:%S"),
            f"{spike['ldavg_1']:.2f}",
            f"{spike['ldavg_5']:.2f}",
            f"{spike['ldavg_15']:.2f}",
            str(spike["blocked"]),
            factor,
            detail[:20],
            trigger[:24],
        ]
        row_line = "  ".join(v.ljust(w) for v, w in zip(row, col_w))
        print(f"  {ld_col}{fc}{row_line}{R}")

    print_section("DEEP DIVE  (±3 min window per spike)")

    for i, spike in enumerate(spikes[:12]):
        dt     = spike["timestamp"]
        cpu    = spike["_cpu"]
        mem    = spike["_mem"]
        io     = spike["_io"]
        csw    = spike["_csw"]
        factor = spike["_factor"]
        fc     = _FACTOR_COLOR.get(factor, R)

        print(f"\n  {BOLD}[Spike {i+1:02d}]  "
              f"{dt.strftime('%Y-%m-%d %H:%M:%S')}  "
              f"ldavg-1={spike['ldavg_1']:.2f}  "
              f"{fc}{factor}{R}  "
              f"runq={spike['runq']}  blocked={spike['blocked']}{R}")

        if cpu:
            idle_col = GRN if cpu["idle"] > 50 else (YEL if cpu["idle"] > 20 else RED)
            print(f"    {BOLD}CPU{R}    user={cpu['user']:.1f}%  "
                  f"sys={cpu['system']:.1f}%  "
                  f"iowait={cpu['iowait']:.1f}%  "
                  f"steal={cpu['steal']:.1f}%  "
                  f"idle={idle_col}{cpu['idle']:.1f}%{R}")
        if mem:
            swp_col = YEL if mem["swpused_pct"] > 5 else GRN
            print(f"    {BOLD}MEM{R}    used={mem['memused_pct']:.1f}%  "
                  f"swap={swp_col}{mem['swpused_pct']:.1f}%{R}  "
                  f"({mem['kbswpused'] // 1024} MB swapped)")
        if io:
            print(f"    {BOLD}I/O{R}    tps={io['tps']:.0f}  "
                  f"read={io['bread_s']:.0f} blk/s  "
                  f"write={io['bwrtn_s']:.0f} blk/s")
        if csw:
            print(f"    {BOLD}CTX{R}    cswch/s={csw['cswch_s']:.0f}  "
                  f"forks/s={csw['proc_s']:.1f}")

        jlines = spike["_journal"]
        if jlines:
            print(f"    {CYN}Journal:{R}")
            for jl in jlines[:8]:
                print(f"      {jl}")
        else:
            print(f"    {YEL}(no journal entries in this window){R}")

    if len(spikes) > 12:
        print(f"\n  ... {len(spikes) - 12} more spikes omitted "
              "(use --date to narrow the time range)")

    print_section("RECOMMENDATIONS")

    dominant = max(factor_counts, key=lambda k: factor_counts[k])
    recs     = recommendations(dominant)

    print(f"\n  Dominant pattern : {BOLD}{_FACTOR_COLOR.get(dominant, R)}{dominant}{R}")
    print(f"  Frequency        : "
          f"{factor_counts[dominant]}/{len(spikes)} spikes\n")

    for rec in recs:
        print(f"  {GRN}▸{R}  {rec}")

    print(f"\n  {BOLD}General:{R}")
    print(f"  {GRN}▸{R}  sar -A -f /var/log/sa/saXX | less")
    print(f"  {GRN}▸{R}  systemctl list-timers --all")
    print(f"  {GRN}▸{R}  journalctl -k --grep='oom_kill' --since=-7d")
    print(f"  {GRN}▸{R}  ps axo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -20")

    print(f"\n{BOLD}{BLU}{'═' * 78}{R}\n")


if __name__ == "__main__":
    main()
