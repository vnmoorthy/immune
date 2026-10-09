#!/usr/bin/env python3
"""
Assemble the Immune product video.

  python3 scripts/video/assemble.py --scenes <dir> --narration <dir-with-narr-1..8.(aiff|wav|m4a)> --out out.mp4 [--hero docs/social-preview.png]
  python3 scripts/video/assemble.py --scenes <dir> --presenter presenter.mp4 --out out.mp4 [--hero ...]

Eight sections (see docs/demo/VOICEOVER.md). Sections 1 and 8 are the presenter full-frame (or the hero still when
there is no presenter recording); sections 2–7 are product footage with the presenter picture-in-picture.
With --presenter, the single take is split into 8 segments on the ~2 s silences between sections.
Each section's footage is trimmed or frozen on its last frame to match that section's narration length.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

W, H, FPS = 1600, 1000, 30
PAD = 0.7  # seconds of air after each narration segment


def run(cmd, quiet=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(" ".join(cmd), file=sys.stderr)
        print(r.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"ffmpeg failed (exit {r.returncode})")
    return r


def duration(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", path], capture_output=True, text=True)
    return float(r.stdout.strip())


def split_on_silence(presenter, n=8, noise="-30dB", min_sil=1.2):
    """Return n (start, end) tuples for the presenter take, cutting at the n-1 longest silences."""
    r = subprocess.run(["ffmpeg", "-i", presenter, "-af", f"silencedetect=noise={noise}:d={min_sil}", "-f", "null", "-"], capture_output=True, text=True)
    starts = [float(x) for x in re.findall(r"silence_start: ([0-9.]+)", r.stderr)]
    ends = [float(x) for x in re.findall(r"silence_end: ([0-9.]+)", r.stderr)]
    sil = [(s, e) for s, e in zip(starts, ends) if e > s]
    total = duration(presenter)
    # ignore leading/trailing silence
    sil = [(s, e) for s, e in sil if s > 0.3 and e < total - 0.3]
    sil.sort(key=lambda x: x[1] - x[0], reverse=True)
    picks = sorted(sil[: n - 1])
    if len(picks) != n - 1:
        print(f"warning: found {len(picks)} usable silences, expected {n - 1}; splitting evenly", file=sys.stderr)
        step = total / n
        return [(i * step, (i + 1) * step) for i in range(n)]
    bounds = [0.0] + [(s + e) / 2 for s, e in picks] + [total]
    return [(bounds[i], bounds[i + 1]) for i in range(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenes", required=True)
    ap.add_argument("--narration")
    ap.add_argument("--presenter")
    ap.add_argument("--hero", default="docs/social-preview.png")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not a.narration and not a.presenter:
        raise SystemExit("need --narration <dir> or --presenter <mp4>")

    cuts = json.load(open(os.path.join(a.scenes, "cuts.json")))
    loop = os.path.join(a.scenes, "loop.webm")
    # section -> (video file, start, end) ; None video = hero/presenter full frame
    sections = {
        1: None,
        2: (os.path.join(a.scenes, "s2-gate.webm"), 2.5, None),  # skip the page warm-up
        3: (loop, cuts["t3"], cuts["t4"]),
        4: (loop, cuts["t4"], cuts["t5"]),
        5: (loop, cuts["t5"], cuts["end"]),
        6: (os.path.join(a.scenes, "s6-proof.webm"), 0.0, None),
        7: (os.path.join(a.scenes, "s7-data.webm"), 4.0, None),  # skip the page warm-up
        8: None,
    }

    tmp = tempfile.mkdtemp(prefix="immune-video-")
    seg_files = []

    # narration per section
    narr = {}
    pres_segments = None
    if a.presenter:
        pres_segments = split_on_silence(a.presenter)
        for i, (s, e) in enumerate(pres_segments, start=1):
            f = os.path.join(tmp, f"narr-{i}.m4a")
            run(["ffmpeg", "-y", "-loglevel", "error", "-ss", f"{s:.3f}", "-t", f"{e - s:.3f}", "-i", a.presenter, "-vn", "-c:a", "aac", "-ar", "48000", "-ac", "2", f])
            narr[i] = f
    else:
        for i in range(1, 9):
            cands = [os.path.join(a.narration, f"narr-{i}.{ext}") for ext in ("aiff", "wav", "m4a", "mp3")]
            f = next((c for c in cands if os.path.exists(c)), None)
            if not f:
                raise SystemExit(f"missing narration for section {i} in {a.narration}")
            narr[i] = f

    for i in range(1, 9):
        a_len = duration(narr[i])
        target = a_len + PAD
        seg = os.path.join(tmp, f"seg-{i}.mp4")
        vf_common = f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:black,fps={FPS},format=yuv420p"
        src = sections[i]
        if src is None:
            if a.presenter:
                s, e = pres_segments[i - 1]
                vin = ["-ss", f"{s:.3f}", "-t", f"{target:.3f}", "-i", a.presenter]
                vfilter = f"[0:v]{vf_common},tpad=stop_mode=clone:stop_duration={PAD + 1:.2f}[v]"
            else:
                vin = ["-loop", "1", "-t", f"{target:.3f}", "-i", a.hero]
                vfilter = f"[0:v]{vf_common}[v]"
        else:
            vfile, s, e = src
            vin = ["-ss", f"{s:.3f}"] + (["-t", f"{(e - s):.3f}"] if e else []) + ["-i", vfile]
            # the recorder leaves a ~24 px grey band under the page canvas: crop it, then fit exactly
            footage = f"crop=iw:ih-24:0:0,scale={W}:{H},fps={FPS},format=yuv420p"
            vfilter = f"[0:v]{footage},tpad=stop_mode=clone:stop_duration=60[v]"  # freeze last frame if footage is shorter than narration
            if a.presenter:
                ps, pe = pres_segments[i - 1]
                vin += ["-ss", f"{ps:.3f}", "-t", f"{target:.3f}", "-i", a.presenter]
                vfilter = (
                    f"[0:v]{footage},tpad=stop_mode=clone:stop_duration=60[bg];"
                    f"[2:v]scale=400:-2,tpad=stop_mode=clone:stop_duration=60[pip];"
                    f"[bg][pip]overlay=W-w-24:H-h-24:shortest=0[v]"
                )
        cmd = ["ffmpeg", "-y", "-loglevel", "error"] + vin + ["-i", narr[i], "-filter_complex", vfilter + ";[1:a]apad[a]" if not (a.presenter and src is not None) else vfilter + ";[1:a]apad[a]",
               "-map", "[v]", "-map", "[a]", "-t", f"{target:.3f}", "-c:v", "libx264", "-preset", "medium", "-crf", "22", "-c:a", "aac", "-b:a", "160k", "-ar", "48000", "-ac", "2", "-r", str(FPS), seg]
        # when presenter PiP is used, narration is input index 1 and presenter index 2 (vin order: footage, presenter, then narration appended last → fix indexes)
        if a.presenter and src is not None:
            # inputs: 0 footage, 1 presenter, 2 narration
            vfilter = vfilter.replace("[2:v]", "[1:v]")
            cmd = ["ffmpeg", "-y", "-loglevel", "error"] + vin + ["-i", narr[i], "-filter_complex", vfilter + ";[2:a]apad[a]",
                   "-map", "[v]", "-map", "[a]", "-t", f"{target:.3f}", "-c:v", "libx264", "-preset", "medium", "-crf", "22", "-c:a", "aac", "-b:a", "160k", "-ar", "48000", "-ac", "2", "-r", str(FPS), seg]
        run(cmd)
        seg_files.append(seg)
        print(f"section {i}: narration {a_len:.1f}s → segment {target:.1f}s")

    lst = os.path.join(tmp, "list.txt")
    with open(lst, "w") as f:
        for s in seg_files:
            f.write(f"file '{s}'\n")
    run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-c", "copy", "-movflags", "+faststart", a.out])
    print(f"wrote {a.out} ({duration(a.out):.1f}s)")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
