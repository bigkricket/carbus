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


def decode_signal(signal_def: Dict, data_bytes: bytes) -> Tuple[Optional[float], str, str]:
    fmt = signal_def.get("fmt") or {}
    bix = int(fmt.get("bix", 0))
    blen = int(fmt.get("len", 0))
    raw = extract_bits_msb(data_bytes, bix, blen)
    sid = str(signal_def.get("id") or signal_def.get("name") or "signal")
    unit = str(fmt.get("unit") or "")
    if raw is None:
        return None, f"{sid}=<n/a>", unit

    if "map" in fmt and isinstance(fmt["map"], dict):
        mapped = fmt["map"].get(str(raw))
        if isinstance(mapped, dict):
            value = mapped.get("value", mapped.get("description", raw))
            return None, f"{sid}={value}", unit
        if mapped is not None:
            return None, f"{sid}={mapped}", unit
        return float(raw), f"{sid}={raw}", unit

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
    return val, f"{sid}={rendered}" + (f" {unit}" if unit else ""), unit


def decode_mode01_frame(
    frame: Frame, pid_defs: Dict[int, Dict]
) -> List[Tuple[str, Optional[float], str, str]]:
    # Positive service 01 response is 0x41: [len, 0x41, pid, ...]
    if len(frame.data) < 3 or frame.data[1] != 0x41:
        return []
    pid = frame.data[2]
    cmd = pid_defs.get(pid)
    if cmd is None:
        return []
    dbytes = response_data_bytes(frame.data)
    out: List[Tuple[str, Optional[float], str, str]] = []
    for sig in cmd.get("signals", []):
        signal_name = str(sig.get("id") or sig.get("name") or f"PID_{pid:02X}")
        num, rendered, unit = decode_signal(sig, dbytes)
        out.append((signal_name, num, rendered, unit))
    return out


def write_decoded_csv(rows: Iterable[Tuple[float, int, str, Optional[float], str]], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid_hex", "signal", "numeric_value", "rendered"])
        for ts, pid, signal, num, rendered in rows:
            writer.writerow([f"{ts:.6f}", f"0x{pid:02X}", signal, "" if num is None else num, rendered])


def write_top_ids_csv(counts: Counter, total_frames: int, duration_s: float, out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["can_id_hex", "count", "percent", "rate_hz"])
        for can_id, count in counts.most_common():
            pct = (100.0 * count / total_frames) if total_frames else 0.0
            hz = (count / duration_s) if duration_s > 0 else 0.0
            writer.writerow([f"0x{can_id:03X}", count, f"{pct:.2f}", f"{hz:.3f}"])


def write_plot_guide(
    out_path: Path,
    duration_s: float,
    total_frames: int,
    obd_frames: int,
    decoded_rows: int,
    top_counts: List[Tuple[int, int]],
    resp_min: int,
    resp_max: int,
) -> None:
    avg_fps = (total_frames / duration_s) if duration_s > 0 else 0.0
    with out_path.open("w", encoding="utf-8") as f:
        f.write("Chart Guide\n")
        f.write("===========\n\n")
        f.write("frame_rate.png\n")
        f.write("- X axis: seconds since start of log.\n")
        f.write("- Y axis: CAN frames per time bin.\n")
        f.write("- Dashed line: average frame rate across the full log.\n\n")
        f.write("top_can_ids.png\n")
        f.write("- Horizontal bars: CAN IDs with the most traffic.\n")
        f.write("- Labels show count and percent of all frames.\n")
        f.write(
            f"- Orange bars are in configured OBD response range: 0x{resp_min:X}..0x{resp_max:X}.\n\n"
        )
        f.write("obd_signals*.png\n")
        f.write("- Time series of all decoded numeric OBD-II signals (if present).\n")
        f.write("- Each subplot is one signal decoded from Mode 01 responses.\n")
        f.write("- Y axis uses the signal unit/metric from PID definitions.\n\n")
        f.write("Run Summary\n")
        f.write("-----------\n")
        f.write(f"Duration (s): {duration_s:.3f}\n")
        f.write(f"Total frames: {total_frames}\n")
        f.write(f"Average frame rate (fps): {avg_fps:.2f}\n")
        f.write(f"Decoded OBD frames: {obd_frames}\n")
        f.write(f"Decoded OBD signal rows: {decoded_rows}\n")
        f.write("Top CAN IDs:\n")
        for can_id, count in top_counts[:10]:
            pct = (100.0 * count / total_frames) if total_frames else 0.0
            f.write(f"- 0x{can_id:03X}: {count} frames ({pct:.2f}%)\n")


def plot_visuals(
    frames: List[Frame],
    numeric_signal_series: Dict[str, List[Tuple[float, float]]],
    signal_units: Dict[str, str],
    outdir: Path,
    show: bool,
    resp_min: int,
    resp_max: int,
) -> bool:
    try:
        import matplotlib.pyplot as plt  # local import for clearer runtime failure
    except ModuleNotFoundError:
        return False

    try:
        plt.style.use("seaborn-v0_8-whitegrid")
    except OSError:
        pass

    t0 = frames[0].ts
    t1 = frames[-1].ts
    duration = max(t1 - t0, 1e-6)

    # Plot 1: global frame rate over time.
    bin_width_s = 0.5 if duration <= 180 else 1.0
    bins = max(20, min(400, int(math.ceil(duration / bin_width_s))))
    bucket_counts = [0] * bins
    for fr in frames:
        idx = min(bins - 1, int((fr.ts - t0) / duration * bins))
        bucket_counts[idx] += 1
    bucket_x = [duration * (i + 0.5) / bins for i in range(bins)]
    avg_per_bin = sum(bucket_counts) / len(bucket_counts)
    peak_per_bin = max(bucket_counts) if bucket_counts else 0
    figs = []

    fig, ax = plt.subplots(figsize=(12, 4))
    figs.append(fig)
    ax.plot(bucket_x, bucket_counts, linewidth=1.4, color="#1f77b4")
    ax.fill_between(bucket_x, bucket_counts, alpha=0.15, color="#1f77b4")
    ax.axhline(avg_per_bin, linestyle="--", linewidth=1.0, color="#444444", label="Average")
    ax.set_title("CAN Traffic Intensity Over Time")
    ax.set_xlabel("Seconds since start")
    ax.set_ylabel(f"Frames per ~{duration / bins:.2f}s bin")
    ax.legend(loc="upper right")
    ax.text(
        0.01,
        0.96,
        f"Peak/bin: {peak_per_bin}\nAvg/bin: {avg_per_bin:.1f}",
        transform=ax.transAxes,
        va="top",
        fontsize=9,
        bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "#BBBBBB"},
    )
    fig.tight_layout()
    fig.savefig(outdir / "frame_rate.png", dpi=150)
    if not show:
        plt.close(fig)

    # Plot 2: top CAN IDs.
    counts = Counter(fr.can_id for fr in frames)
    top = counts.most_common(20)
    ids = [f"0x{cid:03X}" for cid, _ in top]
    vals = [c for _, c in top]
    pct = [(100.0 * c / len(frames)) for c in vals]
    colors = [
        "#ff7f0e" if resp_min <= cid <= resp_max else "#4c78a8" for cid, _ in top
    ]
    fig, ax = plt.subplots(figsize=(12, 5))
    figs.append(fig)
    y = list(range(len(ids)))
    ax.barh(y, vals, color=colors)
    ax.set_yticks(y, labels=ids)
    ax.invert_yaxis()
    ax.set_title("Top CAN IDs by Frame Count")
    ax.set_xlabel("Frame count")
    ax.set_ylabel("CAN ID")
    for i, (count, pct_val) in enumerate(zip(vals, pct)):
        ax.text(count, i, f"  {count} ({pct_val:.1f}%)", va="center", fontsize=9)
    ax.text(
        0.01,
        0.02,
        f"Orange = OBD response range 0x{resp_min:X}..0x{resp_max:X}",
        transform=ax.transAxes,
        fontsize=9,
        bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "#BBBBBB"},
    )
    fig.tight_layout()
    fig.savefig(outdir / "top_can_ids.png", dpi=150)
    if not show:
        plt.close(fig)

    # Plot 3: OBD numeric signals, if any.
    if numeric_signal_series:
        keys = sorted(numeric_signal_series.keys())
        per_fig = 12
        total_pages = math.ceil(len(keys) / per_fig)
        for page in range(total_pages):
            page_keys = keys[page * per_fig : (page + 1) * per_fig]
            n = len(page_keys)
            cols = 1 if n <= 4 else 2
            rows = math.ceil(n / cols)
            fig, axes = plt.subplots(rows, cols, figsize=(14, max(3 * rows, 4)), sharex=True)
            figs.append(fig)
            axes_list = axes.flatten() if hasattr(axes, "flatten") else [axes]
            for i, key in enumerate(page_keys):
                ax = axes_list[i]
                series = numeric_signal_series[key]
                xs = [x - t0 for x, _ in series]
                ys = [y for _, y in series]
                ax.plot(xs, ys, linewidth=1.2, color="#2a9d8f")
                ax.scatter(xs, ys, s=5, alpha=0.35, color="#2a9d8f")
                ax.set_title(key)
                ax.set_xlabel("Seconds")
                unit = signal_units.get(key) or "scalar"
                ax.set_ylabel(unit)
                ax.grid(True, alpha=0.35)
            for j in range(n, len(axes_list)):
                axes_list[j].axis("off")
            fig.suptitle(f"Decoded OBD-II Numeric Signals (Page {page + 1}/{total_pages})")
            fig.tight_layout()
            out_name = "obd_signals.png" if total_pages == 1 else f"obd_signals_{page + 1:02d}.png"
            fig.savefig(outdir / out_name, dpi=150)
            if not show:
                plt.close(fig)
    if show:
        plt.show()
        for fig in figs:
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
    parser.add_argument(
        "--show",
        action="store_true",
        help="Open interactive matplotlib windows in addition to saving PNGs",
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
    signal_units: Dict[str, str] = {}
    obd_frames = 0

    for fr in frames:
        if not (resp_min <= fr.can_id <= resp_max):
            continue
        decoded = decode_mode01_frame(fr, pid_defs)
        if not decoded:
            continue
        obd_frames += 1
        pid = fr.data[2]
        for signal_name, numeric_val, rendered, unit in decoded:
            decoded_rows.append((fr.ts, pid, signal_name, numeric_val, rendered))
            if numeric_val is not None:
                numeric_series[signal_name].append((fr.ts, numeric_val))
                if signal_name not in signal_units and unit:
                    signal_units[signal_name] = unit

    duration_s = max(frames[-1].ts - frames[0].ts, 1e-6)
    counts = Counter(fr.can_id for fr in frames)

    write_decoded_csv(decoded_rows, outdir / "decoded_obd_signals.csv")
    write_top_ids_csv(counts, len(frames), duration_s, outdir / "top_can_ids.csv")
    plotted = plot_visuals(
        frames,
        numeric_series,
        signal_units,
        outdir,
        show=args.show,
        resp_min=resp_min,
        resp_max=resp_max,
    )
    write_plot_guide(
        outdir / "plot_guide.txt",
        duration_s=duration_s,
        total_frames=len(frames),
        obd_frames=obd_frames,
        decoded_rows=len(decoded_rows),
        top_counts=counts.most_common(10),
        resp_min=resp_min,
        resp_max=resp_max,
    )

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
    print(f"Wrote: {outdir / 'top_can_ids.csv'}")
    print(f"Wrote: {outdir / 'plot_guide.txt'}")
    if plotted:
        print(f"Wrote: {outdir / 'frame_rate.png'}")
        print(f"Wrote: {outdir / 'top_can_ids.png'}")
        if numeric_series:
            signal_plots = sorted(outdir.glob("obd_signals*.png"))
            for path in signal_plots:
                print(f"Wrote: {path}")
        else:
            print("No numeric OBD-II signal series found for plotting.")
        if args.show:
            print("Displayed interactive plot windows.")
    else:
        print("matplotlib not installed; skipped PNG visualizations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
