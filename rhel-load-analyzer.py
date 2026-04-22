#!/usr/bin/env python3
"""
rhel-load-analyzer  –  Root Cause Analysis tool for cyclical CPU load spikes on RHEL 8/9.
Uses only standard-library Python 3 + system tools (sysstat/sadf, journalctl, nproc).
Recommended: run as root.
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
    """Context switches via sar -w."""
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
    """
    Return (spikes_list, threshold, ncpu).
    Consecutive samples within 5 minutes are merged, keeping the peak.
    """
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
                merged[-1] = s          # keep only the peak of each burst
        else:
            merged.append(s)

    return merged, threshold, ncpu

# ── journalctl correlation ─────────────────────────────────────────────────────

_TRIGGER_KEYWORDS = [
    "Started", "Stopped", "oom-kill", "oom_kill", "OOM",
    "cron", "backup", "rsync", "dnf", "yum", "ansible",
    "restarted", "activated", "deactivated",
]

def journal_around(dt: datetime, minutes: int = 3) -> list:
    since = (dt - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    until = (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

    lines: list = []

    # Priority 0-4: emerg → warning (always interesting)
    out = run_cmd([
        "journalctl", "--since", since, "--until", until,
        "--no-pager", "-o", "short-iso", "-p", "0..4", "--lines", "15",
    ], timeout=15)
    if out:
        lines += [l for l in out.splitlines() if l and "No entries" not in l]

    # Service lifecycle + well-known noisy actors
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

# ── Spike classification ───────────────────────────────────────────────────────

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

# ── Recommendations ────────────────────────────────────────────────────────────

_RECS: dict[str, list] = {
    "IO-Bound": [
        "tuned-adm profile throughput-performance",
        "echo mq-deadline > /sys/block/<dev>/queue/scheduler",
        "sysctl -w vm.dirty_ratio=10 vm.dirty_background_ratio=3",
        "iostat -xz 1 10          # identify saturated device",
        "lsof +D /path            # find processes holding files open",
    ],
    "CPU-User": [
        "renice +10 -p <pid>      # reduce scheduling priority",
        "systemctl set-property <unit>.service CPUQuota=50%",
        "systemctl list-timers --all   # look for coinciding cron/systemd timers",
        "perf top -p <pid>        # profile hot code paths",
    ],
    "CPU-Kernel": [
        "tuned-adm profile latency-performance",
        "sysctl -w kernel.sched_min_granularity_ns=10000000",
        "cat /proc/interrupts | sort -k2 -rn | head  # check IRQ distribution",
        "perf record -ag -- sleep 10; perf report    # kernel-level flame graph",
    ],
    "MEM-Swap": [
        "sysctl -w vm.swappiness=10",
        "smem -r -s rss | head -15   # identify memory hogs",
        "journalctl -k --grep='oom_kill' --since=-7d",
        "systemctl set-property <unit>.service MemoryMax=2G",
    ],
    "MEM-Paging": [
        "sysctl -w vm.min_free_kbytes=131072",
        "echo never > /sys/kernel/mm/transparent_hugepage/enabled   # disable THP",
        "numactl --hardware && numastat   # check NUMA imbalance",
    ],
    "Unknown": [
        "vmstat 1 20              # broad snapshot: procs, memory, io, cpu",
        "sar -A -f /var/log/sa/saXX | less   # full historical view",
        "strace -c -p <pid>       # syscall breakdown",
        "auditd + aureport        # enable process-level tracing",
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
        description="Root Cause Analysis for cyclical load spikes on RHEL 8/9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 rhel-load-analyzer.py
  sudo python3 rhel-load-analyzer.py --days 7
  sudo python3 rhel-load-analyzer.py --days 14
  sudo python3 rhel-load-analyzer.py --date 21
  sudo python3 rhel-load-analyzer.py --sa-file /var/log/sa/sa21
  sudo python3 rhel-load-analyzer.py --threshold 0.6 --no-color
        """,
    )
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
        warn("Not running as root – journalctl and some sa files may be restricted.")

    if not run_cmd(["sadf", "-V"], timeout=5):
        die("'sadf' not found. Install sysstat:\n"
            "  dnf install sysstat && systemctl enable --now sysstat")

    sa_files = resolve_sa_files(args)
    info(f"Analysing {len(sa_files)} SA file(s): {', '.join(sa_files)}")

    # ── Collect all metrics ────────────────────────────────────────────────────
    all_load   = {}
    all_cpu    = {}
    all_mem    = {}
    all_io     = {}
    all_paging = {}
    all_ctxsw  = {}

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

    # ── Header / summary ───────────────────────────────────────────────────────
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

    # ── Per-spike analysis ─────────────────────────────────────────────────────
    factor_counts: dict[str, int] = {}

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

    # ── Summary table ──────────────────────────────────────────────────────────
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

        fc = _FACTOR_COLOR.get(factor, R)
        ld_col = RED if spike["ldavg_1"] >= threshold * 1.5 else YEL

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

    # ── Deep dive ──────────────────────────────────────────────────────────────
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
              f"{fc}{factor}{R}  runq={spike['runq']}  blocked={spike['blocked']}{R}")

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
            print(f"    {YEL}(no journal entries in this window – check permissions?){R}")

    if len(spikes) > 12:
        print(f"\n  ... {len(spikes) - 12} more spikes omitted "
              "(use --date to narrow the time range)")

    # ── Recommendations ────────────────────────────────────────────────────────
    print_section("RECOMMENDATIONS")

    dominant = max(factor_counts, key=lambda k: factor_counts[k])
    recs     = recommendations(dominant)

    print(f"\n  Dominant pattern : {BOLD}{_FACTOR_COLOR.get(dominant, R)}{dominant}{R}")
    print(f"  Frequency        : "
          f"{factor_counts[dominant]}/{len(spikes)} spikes matched this profile\n")

    for rec in recs:
        print(f"  {GRN}▸{R}  {rec}")

    print(f"\n  {BOLD}General investigation commands:{R}")
    print(f"  {GRN}▸{R}  sar -A -f /var/log/sa/saXX | less")
    print(f"  {GRN}▸{R}  systemctl list-timers --all")
    print(f"  {GRN}▸{R}  journalctl -k --grep='oom_kill' --since=-7d")
    print(f"  {GRN}▸{R}  ps axo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -20")

    print(f"\n{BOLD}{BLU}{'═' * 78}{R}\n")


if __name__ == "__main__":
    main()
