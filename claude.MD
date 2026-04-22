# Prompt: System Performance Analyzer for RHEL (Root Cause Analysis Tool)

## Role
You are an expert Senior Linux System Administrator (RHCE/RHCA level) specializing in performance tuning and troubleshooting on Red Hat Enterprise Linux.

## Objective
Create a professional troubleshooting tool (Bash or Python) named `rhel-load-analyzer`. The tool must identify the root cause of **cyclical CPU load spikes** by correlating data from system logs, performance counters, and process states, using only tools available in the standard Red Hat repositories.

## Context & Environment
* **OS:** RHEL 8/9.
* **Constraints:** No external dependencies (no pip, no third-party repos). Use `sysstat` (sar), `procps-ng`, `util-linux`, and `systemd-journal`.
* **Problem:** The system experiences periodic performance degradation (load average spikes). We need to know *what* is running, *why* it's queuing, and *when* it correlates with system events.

## Functional Requirements

### 1. Data Sources to Analyze
The tool should parse and correlate:
* **`sar` (sysstat):** Analyze historical CPU (`sar -u`), Memory (`sar -r`), and I/O (`sar -b`). Focus on `%iowait`, `%system`, and `%user`.
* **`journalctl`:** Extract errors or specific service triggers (e.g., cron jobs, OOM killer, backup services) around the spike timestamps.
* **`top/ps` snapshots:** If running in "live-monitor" mode, capture the top 10 processes by CPU/Memory during a load spike.
* **`vmstat`:** Look for context switching and interrupts.

### 2. Analytical Logic
The script should:
1.  **Detect Spikes:** Identify timestamps where Load Average exceeds a defined threshold (e.g., `n_cores * 0.8`).
2.  **Cross-Reference:** For every detected spike, look at `sar` data 2 minutes before and after.
3.  **Identify Patterns:** Determine if the spike is:
    * **I/O Bound:** High `%iowait` + specific disk activity.
    * **CPU Bound:** High `%user` or `%system` (kernel contention).
    * **Memory Bound:** High swap activity or "Major Page Faults".
4.  **Process Attribution:** Identify the most likely process "villain" based on the timing of cron/systemd units.

### 3. Output Format
Provide a detailed report in the following structure:
* **Summary:** Peak load values and frequency of cycles.
* **Correlation Table:** Timestamp | Load | Dominant Factor (CPU/IO/MEM) | Suspected Process/Service.
* **Deep Dive:** Snippets from logs at the exact moment of the spike.
* **Recommendations:** Specific RHEL tuning suggestions (e.g., `tuned-adm` profiles, `sysctl` tweaks).

## Technical Implementation Details
* **Language:** Python 3 (standard library) or Bash.
* **Execution:** Must be runnable as `root` to access all logs.
* **Input:** Allow passing a specific date or a `sa` binary file (e.g., `/var/log/sa/sa21`).

## Example Logic Flow
[Identify Spike] -> [Query `sar -q` for that time] -> [Check `journalctl --since --until`] -> [Check `systemctl list-timers` for scheduled tasks] -> [Output Diagnosis].
