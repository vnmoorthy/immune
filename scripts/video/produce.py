#!/usr/bin/env python3
"""
Produce the Immune product video: the presenter's single take drives one continuous timeline; the presenter
stays in a circle bottom-left; the background switches between animated cards and product footage at the
section boundaries with crossfades; lower-third captions fade in at each section.

  python3 scripts/video/produce.py --take voiceover.mov --scenes <dir> --captions <dir> \
      (--words words.json | --bounds 20.1,41.3,...)  --out docs/demo/immune-product-video.mp4

<dir> comes from scripts/video/record-pro.mjs (intro/s2-gate/loop(+cuts.json)/s6-proof/s7-stack/outro.webm);
captions from scripts/video/render-cards.mjs; words.json from a word-timestamped transcript of the take.
"""
import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

W, H, FPS = 1600, 1000, 30
XF = 0.7          # crossfade seconds
CIRCLE = 360      # presenter circle diameter
MARGIN = 40
CAP_SHOW = 6.5    # caption on-screen seconds
CAP_DELAY = 0.9   # after the section starts

# first words of each section in docs/demo/VOICEOVER-3MIN.md (section 1 starts at 0)
ANCHORS = {
    2: "this is the command center",
    3: "but attackers adapt",
    4: "not immune watch the right side",
    5: "and here's my favorite part",
    6: "every antibody carries its proof",
    7: "every decision is a row in clickhouse",
    8: "detectors are a commodity the loop is the product",
}
# fallback proportional split by script word counts (sections 1..8)
SCRIPT_WORDS = [75, 70, 68, 120, 62, 58, 62, 45]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(" ".join(cmd), file=sys.stderr)
        print(r.stderr[-3000:], file=sys.stderr)
        raise SystemExit(f"ffmpeg failed ({r.returncode})")


def duration(p):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", p], capture_output=True, text=True)
    return float(r.stdout.strip())


def norm(s):
    return re.sub(r"[^a-z0-9' ]+", " ", s.lower()).split()


def find_bounds(words_json, total):
    """Section start times from the transcript, fuzzy-matched on the anchor phrases, monotonic."""
    data = json.load(open(words_json))
    toks = [(norm(w["w"]) or [""])[0] for w in data["words"]]
    starts = [w["s"] for w in data["words"]]
    bounds = [0.0]
    last_i = 0
    for sec in range(2, 9):
        anchor = norm(ANCHORS[sec])
        n = len(anchor)
        best, best_i = 0.0, None
        for i in range(last_i, len(toks) - n + 1):
            r = difflib.SequenceMatcher(None, toks[i:i + n], anchor).ratio()
            if r > best:
                best, best_i = r, i
                if r == 1.0:
                    break
        if best_i is None or best < 0.62:
            print(f"section {sec}: anchor not found (best {best:.2f}); using proportional split", file=sys.stderr)
            frac = sum(SCRIPT_WORDS[: sec - 1]) / sum(SCRIPT_WORDS)
            t = max(bounds[-1] + 3.0, frac * total)
        else:
            t = max(bounds[-1] + 3.0, starts[best_i] - 0.25)
            last_i = best_i + n
            print(f"section {sec}: '{' '.join(toks[best_i:best_i + n])}' @ {starts[best_i]:.2f}s (match {best:.2f})", file=sys.stderr)
        bounds.append(round(t, 3))
    bounds.append(total)
    return bounds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--take", required=True)
    ap.add_argument("--scenes", required=True)
    ap.add_argument("--captions", required=True)
    ap.add_argument("--words")
    ap.add_argument("--bounds", help="comma-separated start times of sections 2..8")
    ap.add_argument("--out", required=True)
    ap.add_argument("--face", default="0.5,0.5", help="face centre as fractions of the take frame, x,y")
    a = ap.parse_args()

    total = duration(a.take)
    if a.bounds:
        b = [0.0] + [float(x) for x in a.bounds.split(",")] + [total]
    elif a.words:
        b = find_bounds(a.words, total)
    else:
        raise SystemExit("need --words or --bounds")
    assert len(b) == 9, b
    L = [b[i + 1] - b[i] for i in range(8)]
    print("sections:", " ".join(f"{i + 1}:{L[i]:.1f}s" for i in range(8)), f"total {total:.1f}s")

    cuts = json.load(open(os.path.join(a.scenes, "cuts.json")))
    loop = os.path.join(a.scenes, "loop.webm")
    # Sections 3–5 play the loop scene CONTINUOUSLY (no jumps, no freezes): the replay click (t5) is pinned to the
    # start of section 5, and sections 3+4 run backwards from it, so the breach lands mid-section-3 and the theatre
    # fills during section 4 exactly as the narration describes.
    s3_start = max(0.0, min(cuts["t3"] - 6.0, cuts["t5"] - (L[2] + L[3])))
    s4_start = s3_start + L[2]
    s5_start = cuts["t5"] if s4_start + L[3] <= cuts["t5"] + 0.5 else s4_start + L[3]
    src = {
        1: (os.path.join(a.scenes, "intro.webm"), 0.6, None, False),
        2: (os.path.join(a.scenes, "s2-gate.webm"), 2.0, None, True),
        3: (loop, s3_start, None, True),
        4: (loop, s4_start, None, True),
        5: (loop, s5_start, None, True),
        6: (os.path.join(a.scenes, "s6-proof.webm"), float(os.environ.get("S6_START", "20.5")), None, True),
        7: (os.path.join(a.scenes, "s7-stack.webm"), float(os.environ.get("S7_START", "2.0")), None, True),
        8: (os.path.join(a.scenes, "outro.webm"), 0.6, None, False),
    }
    print(f"loop mapping: s3 {s3_start:.1f}s · s4 {s4_start:.1f}s · s5 {s5_start:.1f}s (breach at {cuts['t4']:.1f}, replay at {cuts['t5']:.1f})")

    tmp = tempfile.mkdtemp(prefix="immune-pro-")
    try:
        # ---- pass A: one background segment per section, length L_i + XF (except the last), frozen if short
        segs = []
        for i in range(1, 9):
            f, s, e, is_ui = src[i]
            need = L[i - 1] + (XF if i < 8 else 0)
            vin = ["-ss", f"{s:.3f}"] + (["-t", f"{(e - s):.3f}"] if e else []) + ["-i", f]
            if is_ui:
                # drop the recorder's grey band, then a slow drift so static UI never feels frozen
                motion = (f"crop=iw:ih-24:0:0,scale={W + 56}:{H + 36},"
                          f"crop={W}:{H}:x='(iw-ow)/2+22*sin(t/9)':y='(ih-oh)/2+12*sin(t/13)'")
            else:
                motion = f"scale={W}:{H}"
            vf = f"{motion},fps={FPS},format=yuv420p,tpad=stop_mode=clone:stop_duration=600,trim=duration={need:.3f},setpts=PTS-STARTPTS"
            seg = os.path.join(tmp, f"seg-{i}.mp4")
            run(["ffmpeg", "-y", "-loglevel", "error"] + vin + ["-an", "-vf", vf, "-t", f"{need:.3f}", "-c:v", "libx264", "-preset", "veryfast", "-crf", "18", "-r", str(FPS), seg])
            segs.append(seg)
            print(f"  seg {i}: {need:.1f}s from {os.path.basename(f)}@{s:.1f}")

        # ---- pass B: crossfade join
        ins = []
        for sg in segs:
            ins += ["-i", sg]
        fc, prev, off = "", "[0:v]", 0.0
        for k in range(1, 8):
            off += L[k - 1]
            fc += f"{prev}[{k}:v]xfade=transition=fade:duration={XF}:offset={off - XF:.3f}[x{k}];"
            prev = f"[x{k}]"
        bg = os.path.join(tmp, "bg.mp4")
        run(["ffmpeg", "-y", "-loglevel", "error"] + ins + ["-filter_complex", fc.rstrip(";"), "-map", prev, "-c:v", "libx264", "-preset", "veryfast", "-crf", "18", "-r", str(FPS), bg])
        print(f"  background joined: {duration(bg):.1f}s")

        # ---- pass C: presenter circle + captions + normalized voice
        fx, fy = [float(x) for x in a.face.split(",")]
        d = CIRCLE
        r_in, r_out = d / 2 - 4, d / 2
        circle = (
            f"[1:v]fps={FPS},crop='min(iw,ih)':'min(iw,ih)':'(iw-min(iw,ih))*{fx}':'(ih-min(iw,ih))*{fy}',"
            f"scale={d}:{d},format=yuva420p,"
            f"geq=lum='p(X,Y)':cb='p(X,Y)':cr='p(X,Y)':a='if(lte(pow(X-{d/2},2)+pow(Y-{d/2},2),pow({r_in},2)),255,0)',"
            f"tpad=stop_mode=clone:stop_duration=600[face];"
            # soft shadow + emerald ring, drawn once and looped
            f"color=c=black@0.0:s={d + 60}x{d + 60}:r={FPS},format=yuva420p,"
            f"geq=lum=0:cb=128:cr=128:a='if(lte(pow(X-{(d + 60) / 2},2)+pow(Y-{(d + 60) / 2},2),pow({r_out + 6},2)),150,0)',gblur=sigma=14[shadow];"
            f"color=c=0x3ecf8e:s={d}x{d}:r={FPS},format=yuva420p,"
            f"geq=lum='p(X,Y)':cb='p(X,Y)':cr='p(X,Y)':a='if(between(pow(X-{d/2},2)+pow(Y-{d/2},2),pow({r_in - 1},2),pow({r_out},2)),255,0)'[ring];"
            f"[0:v][shadow]overlay={MARGIN - 30}:{H - d - MARGIN - 30 + 10}:shortest=1[b1];"
            f"[b1][ring]overlay={MARGIN}:{H - d - MARGIN}:shortest=1[b2];"
            f"[b2][face]overlay={MARGIN}:{H - d - MARGIN}:shortest=1[b3]"
        )
        cap_in, cap_fc, prev = [], "", "[b3]"
        for i in range(1, 9):
            png = os.path.join(a.captions, f"caption-{i}.png")
            if not os.path.exists(png):
                continue
            s = b[i - 1] + CAP_DELAY
            e = min(s + CAP_SHOW, b[i] - 0.4)
            if e - s < 1.5:
                continue
            idx = 2 + len(cap_in) // 2
            cap_in += ["-loop", "1", "-t", f"{total:.3f}", "-i", png]
            cap_fc += (f"[{idx}:v]format=rgba,fps={FPS},fade=t=in:st={s:.2f}:d=0.5:alpha=1,fade=t=out:st={e - 0.5:.2f}:d=0.5:alpha=1[c{i}];"
                       f"{prev}[c{i}]overlay=0:0:enable='between(t,{s:.2f},{e:.2f})':shortest=1[o{i}];")
            prev = f"[o{i}]"
        audio = "[1:a]highpass=f=80,loudnorm=I=-16:TP=-1.5:LRA=11,aformat=sample_rates=48000:channel_layouts=stereo[a]"
        fc = circle + ";" + cap_fc + audio
        run(["ffmpeg", "-y", "-loglevel", "error", "-i", bg, "-i", a.take] + cap_in +
            ["-filter_complex", fc, "-map", prev, "-map", "[a]", "-t", f"{total:.3f}",
             "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p", "-r", str(FPS),
             "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", a.out])
        print(f"wrote {a.out} ({duration(a.out):.1f}s)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
