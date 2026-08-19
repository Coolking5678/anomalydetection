"""
src/ingestion.py
----------------
Handles downloading the SSH log dataset and parsing raw log lines into a
clean, structured pandas DataFrame.

Supported log format (Linux/OpenSSH syslog style):
    Month DD HH:MM:SS hostname sshd[PID]: message
"""

import os
import re
import sys
import logging
from pathlib import Path
from urllib.request import urlretrieve
from urllib.error import URLError

import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Primary URL (OpenSSH dataset, same format as the original SSH_2k.log)
LOG_URL = (
    "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
)
# Fallback URLs tried in order if primary fails
_FALLBACK_URLS = [
    "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log",
]
# Resolve the base directory correctly whether running from source or a
# PyInstaller-bundled .exe.  When frozen, __file__ lives inside a temp
# extraction folder (_MEIPASS) that is deleted on exit — so we anchor data/
# next to the actual .exe instead.
if getattr(sys, "frozen", False):
    # Running as PyInstaller bundle
    _BASE_DIR = Path(sys.executable).resolve().parent
else:
    # Running from source
    _BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = _BASE_DIR / "data"
DEFAULT_LOG_PATH = DATA_DIR / "SSH_2k.log"

# Map raw keyword patterns → canonical event type labels
EVENT_MAP = {
    "Failed password": "FAILED_LOGIN",
    "Invalid user": "INVALID_USER",
    "Accepted password": "SUCCESS_LOGIN",
    "Accepted publickey": "SUCCESS_LOGIN",
    "Accepted keyboard-interactive": "SUCCESS_LOGIN",
}

# Compiled regex patterns
_RE_LOG = re.compile(
    r"(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+"                          # hostname
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)"
)
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_USER = re.compile(
    r"(?:Invalid user|for user|for)\s+(\S+)", re.IGNORECASE
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def _generate_synthetic_log(dest: Path, n_lines: int = 2000) -> None:
    """
    Write a synthetic SSH authentication log to *dest* when no network is
    available.  The generated log mimics the standard OpenSSH syslog format
    and contains realistic normal + attack traffic patterns.
    """
    import random
    from datetime import datetime, timedelta

    random.seed(42)
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    # Attacker IPs (will generate high failure bursts)
    attacker_ips = ["218.65.30.126", "61.177.172.55", "103.99.0.122", "45.33.32.156"]
    # Legitimate IPs
    legit_ips = ["10.0.0.5", "192.168.1.10", "172.16.0.3"]
    legit_users = ["john", "alice", "deploy", "bob"]
    admin_users = ["root", "admin", "test"]

    lines = []
    base_dt = datetime(datetime.now().year, 1, 1, 8, 0, 0)
    delta = timedelta(seconds=0)

    for i in range(n_lines):
        # Mix: 60% failed/invalid, 15% success, 25% other
        roll = random.random()
        dt = base_dt + delta
        month = months[dt.month - 1]
        ts = f"{month} {dt.day:2d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        pid = random.randint(10000, 65000)
        prefix = f"{ts} combo sshd[{pid}]:"

        if roll < 0.45:
            # Brute-force: attacker IPs, fast bursts
            ip = random.choice(attacker_ips)
            user = random.choice(admin_users + ["guest", "oracle"])
            lines.append(f"{prefix} Failed password for {user} from {ip} port {random.randint(1024,65000)} ssh2")
            delta += timedelta(seconds=random.uniform(0.1, 2))
        elif roll < 0.65:
            # Invalid user attempts
            ip = random.choice(attacker_ips)
            user = random.choice(["admin", "ftp", "mail", "postgres", "pi"])
            lines.append(f"{prefix} Invalid user {user} from {ip}")
            delta += timedelta(seconds=random.uniform(0.5, 3))
        elif roll < 0.80:
            # Successful login (legit)
            ip = random.choice(legit_ips)
            user = random.choice(legit_users)
            lines.append(f"{prefix} Accepted password for {user} from {ip} port {random.randint(1024,65000)} ssh2")
            delta += timedelta(minutes=random.uniform(5, 30))
        elif roll < 0.90:
            # Off-hours access
            ip = random.choice(attacker_ips + legit_ips)
            user = random.choice(admin_users)
            off_hour_dt = dt.replace(hour=random.choice([1, 2, 3, 4, 23]))
            off_ts = f"{months[off_hour_dt.month - 1]} {off_hour_dt.day:2d} {off_hour_dt.hour:02d}:{off_hour_dt.minute:02d}:{off_hour_dt.second:02d}"
            lines.append(f"{off_ts} combo sshd[{pid}]: Failed password for {user} from {ip} port 22 ssh2")
            delta += timedelta(minutes=random.uniform(1, 10))
        else:
            # Misc sshd messages
            lines.append(f"{prefix} Received disconnect from {random.choice(legit_ips)}: 11: disconnected by user")
            delta += timedelta(seconds=random.uniform(10, 60))

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Synthetic log written to '%s' (%d lines).", dest, len(lines))


def download_log(url: str = LOG_URL, dest: Path = DEFAULT_LOG_PATH) -> Path:
    """
    Download the SSH log file from *url* to *dest* if it does not already
    exist on disk.  Tries *url* first, then ``_FALLBACK_URLS``.  If all
    network attempts fail, generates a realistic synthetic log instead.

    Parameters
    ----------
    url  : Primary remote URL to fetch.
    dest : Local filesystem destination path.

    Returns
    -------
    Path to the local log file.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        logger.info("Log file already present at '%s'. Skipping download.", dest)
        return dest

    all_urls = [url] + _FALLBACK_URLS
    last_exc: Exception | None = None

    for attempt_url in all_urls:
        logger.info("Downloading log file from '%s' …", attempt_url)
        try:
            urlretrieve(attempt_url, dest)
            logger.info("Download complete → '%s'.", dest)
            return dest
        except URLError as exc:
            logger.warning("Download failed for '%s': %s", attempt_url, exc)
            last_exc = exc
            # Remove partial download if any
            if dest.exists():
                dest.unlink()

    logger.warning(
        "All download URLs failed. Generating synthetic log at '%s'.", dest
    )
    _generate_synthetic_log(dest)
    return dest


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _classify_event(message: str) -> str:
    """Return a canonical event-type string for a raw log message."""
    for keyword, label in EVENT_MAP.items():
        if keyword in message:
            return label
    return "OTHER"


def _extract_ip(message: str) -> str:
    """Return the first IPv4 address found in *message*, or empty string."""
    match = _RE_IP.search(message)
    return match.group(0) if match else ""


def _extract_username(message: str) -> str:
    """Return the best-guess target username from a log message."""
    match = _RE_USER.search(message)
    if match:
        return match.group(1)
    # Fallback: look for 'user <name>'
    fallback = re.search(r"user\s+(\S+)", message, re.IGNORECASE)
    return fallback.group(1) if fallback else ""


# ---------------------------------------------------------------------------
# Public parse function
# ---------------------------------------------------------------------------

def parse_log_file(log_path: str | Path) -> pd.DataFrame:
    """
    Parse a Linux SSH authentication log file into a tidy DataFrame.

    Each row corresponds to one log entry that matched the expected sshd
    format.  Lines that cannot be parsed are silently skipped.

    Parameters
    ----------
    log_path : Absolute or relative path to the ``.log`` file.

    Returns
    -------
    pd.DataFrame with columns:
        - timestamp   (datetime64[ns])
        - event_type  (str)  – FAILED_LOGIN / SUCCESS_LOGIN / INVALID_USER / OTHER
        - source_ip   (str)
        - username    (str)
        - raw_message (str)
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: '{log_path}'")

    records: list[dict] = []
    # We assume the log is from the current or previous year; use a fixed year
    # so pandas can parse timestamps correctly.
    year = pd.Timestamp.now().year

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            match = _RE_LOG.match(line)
            if not match:
                continue

            gd = match.groupdict()
            raw_ts = f"{gd['month']} {gd['day'].zfill(2)} {year} {gd['time']}"
            try:
                ts = pd.to_datetime(raw_ts, format="%b %d %Y %H:%M:%S")
            except ValueError:
                continue

            message = gd["message"]
            records.append(
                {
                    "timestamp": ts,
                    "event_type": _classify_event(message),
                    "source_ip": _extract_ip(message),
                    "username": _extract_username(message),
                    "raw_message": message,
                }
            )

    if not records:
        raise ValueError(
            f"No parseable sshd log entries found in '{log_path}'. "
            "Ensure the file uses standard Linux syslog SSH format."
        )

    df = pd.DataFrame(records)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    logger.info(
        "Parsed %d log entries from '%s'.", len(df), log_path.name
    )
    return df
