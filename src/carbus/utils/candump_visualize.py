#!/usr/bin/env python3
"""Process candump logs and generate visualizations + optional OBD-II decoding."""

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


CANDUMP_HASH_RE = re.compile(
    r"^\((?P<ts>\d+\.\d+)\)\s+(?P<iface>\S+)\s+(?P<can_id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)$"
)
CANDUMP_BRACKET_RE = re.compile(
    r"^\((?P<ts>[^)]+)\)\s+(?P<iface>\S+)\s+(?P<can_id>[0-9A-Fa-f]+)\s+\[(?P<dlc>\d+)\]\s+(?P<data>[0-9A-Fa-f ]*)$"
)


@dataclass
class Frame:
    ts: float
    iface: str
    can_id: int
    data: bytes


def parse_timestamp(raw: str) -> Optional[float]:
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


def parse_candump_line(line: str) -> Optional[Frame]:
    text = line.strip()

    # Format: "(<ts>) <iface> <canid>#<hexdata>"
    m_hash = CANDUMP_HASH_RE.match(text)
    if m_hash:
        data_hex = m_hash.group("data")
        if len(data_hex) % 2 != 0:
            return None
        ts = parse_timestamp(m_hash.group("ts"))
        if ts is None:
            return None
        return Frame(
            ts=ts,
            iface=m_hash.group("iface"),
            can_id=int(m_hash.group("can_id"), 16),
            data=bytes.fromhex(data_hex),
        )

    # Format: "(<ts>) <iface> <canid> [<dlc>] <byte byte ...>"
    m_bracket = CANDUMP_BRACKET_RE.match(text)
    if m_bracket:
        ts = parse_timestamp(m_bracket.group("ts"))
        if ts is None:
            return None

        data_hex = "".join(m_bracket.group("data").split())
        if len(data_hex) % 2 != 0:
            return None

        try:
            declared_dlc = int(m_bracket.group("dlc"))
        except ValueError:
            return None

        payload = bytes.fromhex(data_hex) if data_hex else b""
        if len(payload) < declared_dlc:
            return None

        return Frame(
            ts=ts,
            iface=m_bracket.group("iface"),
            can_id=int(m_bracket.group("can_id"), 16),
            data=payload[:declared_dlc],
        )
    return None


def load_frames(path: Path) -> List[Frame]:
    out: List[Frame] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            frame = parse_candump_line(line)
            if frame is not None:
                out.append(frame)
    return out


def load_mode01_defs(json_path: Path) -> Dict[int, Dict]:
    with json_path.open("r", encoding="utf-8") as f:
        doc = json.load(f)
    defs: Dict[int, Dict] = {}
    for cmd in doc.get("commands", []):
        mode_pid = cmd.get("cmd", {})
        if "01" not in mode_pid:
            continue
        pid = int(mode_pid["01"], 16)
        defs[pid] = cmd
    return defs


def response_data_bytes(payload: bytes) -> bytes:
    if len(payload) < 4:
        return b""
    reported_len = int(payload[0])
    if reported_len >= 2:
        end = min(len(payload), 1 + reported_len)
        return payload[3:end]
    return payload[3:]


def extract_bits_msb(data: bytes, bix: int, blen: int) -> Optional[int]:
    if blen <= 0:
        return None
    total_bits = len(data) * 8
    if bix < 0 or bix + blen > total_bits:
        return None
    buf = int.from_bytes(data, "big", signed=False)
    shift = total_bits - (bix + blen)
    return (buf >> shift) & ((1 << blen) - 1)


def decode_signal(signal_def: Dict, data_bytes: bytes) -> Tuple[Optional[float], str]:
    fmt = signal_def.get("fmt") or {}
    bix = int(fmt.get("bix", 0))
    blen = int(fmt.get("len", 0))
    raw = extract_bits_msb(data_bytes, bix, blen)
    sid = str(signal_def.get("id") or signal_def.get("name") or "signal")
    unit = str(fmt.get("unit") or "")
    if raw is None:
        return None, f"{sid}=<n/a>"

    if "map" in fmt and isinstance(fmt["map"], dict):
        mapped = fmt["map"].get(str(raw))
        if isinstance(mapped, dict):
            value = mapped.get("value", mapped.get("description", raw))
            return None, f"{sid}={value}"
        if mapped is not None:
            return None, f"{sid}={mapped}"
        return float(raw), f"{sid}={raw}"

    val = float(raw)
    if "mul" in fmt:
        val *= float(fmt["mul"])
    if "div" in fmt and float(fmt["div"]) != 0:
        val /= float(fmt["div"])
    if "add" in fmt:
        val += float(fmt["add"])
    if val.is_integer():
        rendered = str(int(val))
    else:
        rendered = f"{val:.6f}".rstrip("0").rstrip(".")
    return val, f"{sid}={rendered}" + (f" {unit}" if unit else "")


def decode_mode01_frame(frame: Frame, pid_defs: Dict[int, Dict]) -> List[Tuple[str, Optional[float], str]]:
    # Positive service 01 response is 0x41: [len, 0x41, pid, ...]
    if len(frame.data) < 3 or frame.data[1] != 0x41:
        return []
    pid = frame.data[2]
    cmd = pid_defs.get(pid)
    if cmd is None:
        return []
    dbytes = response_data_bytes(frame.data)
    out: List[Tuple[str, Optional[float], str]] = []
    for sig in cmd.get("signals", []):
        signal_name = str(sig.get("id") or sig.get("name") or f"PID_{pid:02X}")
        num, rendered = decode_signal(sig, dbytes)
        out.append((signal_name, num, rendered))
    return out


def write_decoded_csv(rows: Iterable[Tuple[float, int, str, Optional[float], str]], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid_hex", "signal", "numeric_value", "rendered"])
        for ts, pid, signal, num, rendered in rows:
            writer.writerow([f"{ts:.6f}", f"0x{pid:02X}", signal, "" if num is None else num, rendered])


def plot_visuals(
    frames: List[Frame],
    numeric_signal_series: Dict[str, List[Tuple[float, float]]],
    outdir: Path,
) -> bool:
    try:
        import matplotlib.pyplot as plt  # local import for clearer runtime failure
    except ModuleNotFoundError:
        return False

    t0 = frames[0].ts
    t1 = frames[-1].ts
    duration = max(t1 - t0, 1e-6)

    # Plot 1: global frame rate over time.
    bins = max(20, min(300, int(duration)))
    bucket_counts = [0] * bins
    for fr in frames:
        idx = min(bins - 1, int((fr.ts - t0) / duration * bins))
        bucket_counts[idx] += 1
    bucket_x = [t0 + (duration * (i + 0.5) / bins) for i in range(bins)]
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot([x - t0 for x in bucket_x], bucket_counts, linewidth=1.2)
    ax.set_title("CAN Frame Rate Over Time")
    ax.set_xlabel("Seconds since start")
    ax.set_ylabel(f"Frames per ~{duration / bins:.2f}s bin")
    fig.tight_layout()
    fig.savefig(outdir / "frame_rate.png", dpi=150)
    plt.close(fig)

    # Plot 2: top CAN IDs.
    counts = Counter(fr.can_id for fr in frames)
    top = counts.most_common(20)
    ids = [f"{cid:03X}" for cid, _ in top]
    vals = [c for _, c in top]
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(ids, vals)
    ax.set_title("Top CAN IDs by Frame Count")
    ax.set_xlabel("CAN ID (hex)")
    ax.set_ylabel("Frame count")
    ax.tick_params(axis="x", rotation=45)
    fig.tight_layout()
    fig.savefig(outdir / "top_can_ids.png", dpi=150)
    plt.close(fig)

    # Plot 3: OBD numeric signals, if any.
    if numeric_signal_series:
        keys = sorted(numeric_signal_series.keys())[:12]
        n = len(keys)
        cols = 2
        rows = math.ceil(n / cols)
        fig, axes = plt.subplots(rows, cols, figsize=(14, max(3 * rows, 4)))
        axes_list = axes.flatten() if hasattr(axes, "flatten") else [axes]
        for i, key in enumerate(keys):
            ax = axes_list[i]
            series = numeric_signal_series[key]
            xs = [x - t0 for x, _ in series]
            ys = [y for _, y in series]
            ax.plot(xs, ys, linewidth=1.0)
            ax.set_title(key)
            ax.set_xlabel("Seconds")
            ax.set_ylabel("Value")
        for j in range(n, len(axes_list)):
            axes_list[j].axis("off")
        fig.suptitle("Decoded OBD-II Numeric Signals")
        fig.tight_layout()
        fig.savefig(outdir / "obd_signals.png", dpi=150)
        plt.close(fig)
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Process a candump log and generate visualizations."
    )
    parser.add_argument("log", help="Path to candump .log or .txt file")
    parser.add_argument(
        "--json",
        default="src/carbus/data/saej1979_default.json",
        help="Path to SAEJ1979 default.json",
    )
    parser.add_argument(
        "--outdir",
        default="candump_reports",
        help="Output directory for plots and CSV",
    )
    parser.add_argument(
        "--response-min",
        default="0x7E8",
        help="Lowest OBD response ID to decode",
    )
    parser.add_argument(
        "--response-max",
        default="0x7EF",
        help="Highest OBD response ID to decode",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log_path = Path(args.log)
    if not log_path.exists():
        raise FileNotFoundError(f"log file not found: {log_path}")

    json_path = Path(args.json)
    if not json_path.exists():
        raise FileNotFoundError(f"json file not found: {json_path}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    frames = load_frames(log_path)
    if not frames:
        print("No parseable candump frames found.")
        return 1
    frames.sort(key=lambda f: f.ts)

    pid_defs = load_mode01_defs(json_path)
    resp_min = int(args.response_min, 0)
    resp_max = int(args.response_max, 0)

    decoded_rows: List[Tuple[float, int, str, Optional[float], str]] = []
    numeric_series: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
    obd_frames = 0

    for fr in frames:
        if not (resp_min <= fr.can_id <= resp_max):
            continue
        decoded = decode_mode01_frame(fr, pid_defs)
        if not decoded:
            continue
        obd_frames += 1
        pid = fr.data[2]
        for signal_name, numeric_val, rendered in decoded:
            decoded_rows.append((fr.ts, pid, signal_name, numeric_val, rendered))
            if numeric_val is not None:
                numeric_series[signal_name].append((fr.ts, numeric_val))

    write_decoded_csv(decoded_rows, outdir / "decoded_obd_signals.csv")
    plotted = plot_visuals(frames, numeric_series, outdir)

    with (outdir / "summary.txt").open("w", encoding="utf-8") as f:
        f.write(f"log: {log_path}\n")
        f.write(f"total_frames: {len(frames)}\n")
        f.write(f"obd_frames_decoded: {obd_frames}\n")
        f.write(f"decoded_signal_rows: {len(decoded_rows)}\n")
        f.write(f"numeric_signal_series: {len(numeric_series)}\n")

    print(f"Processed {len(frames)} frames.")
    print(f"Decoded OBD-II frames: {obd_frames}")
    print(f"Wrote: {outdir / 'summary.txt'}")
    print(f"Wrote: {outdir / 'decoded_obd_signals.csv'}")
    if plotted:
        print(f"Wrote: {outdir / 'frame_rate.png'}")
        print(f"Wrote: {outdir / 'top_can_ids.png'}")
        if numeric_series:
            print(f"Wrote: {outdir / 'obd_signals.png'}")
        else:
            print("No numeric OBD-II signal series found for plotting.")
    else:
        print("matplotlib not installed; skipped PNG visualizations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
