#!/usr/bin/env python3
"""
Narration for the product video: one audio file per section (narr-1..8) from a VOICEOVER markdown file.

  python3 scripts/video/narrate.py --script docs/demo/VOICEOVER-FAST.md --out <dir> [--provider elevenlabs|say] [--voice <id|name>] [--rate 1.0]

Providers
  elevenlabs  ELEVENLABS_API_KEY required (sponsor key). Default voice: ELEVENLABS_VOICE_ID or "Adam". Model eleven_multilingual_v2.
  say         macOS built-in voice (default Samantha). Zero-key fallback.

Then: python3 scripts/video/assemble.py --scenes <scenes> --narration <dir> --out docs/demo/immune-product-video.mp4
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request


def sections(md_path):
    md = open(md_path, encoding="utf-8").read()
    parts = re.split(r"\n\*\*(\d) · [^\n]*\n", md)
    out = {}
    for i in range(1, len(parts) - 1, 2):
        out[int(parts[i])] = parts[i + 1].strip().split("\n\n")[0].strip()
    if len(out) != 8:
        raise SystemExit(f"expected 8 sections, found {sorted(out)}")
    return out


def say(text, path, voice, rate):
    subprocess.run(["say", "-v", voice or "Samantha", "-r", str(int(178 * rate)), "-o", path, text], check=True)


def elevenlabs(text, path, voice, rate):
    key = os.environ.get("ELEVENLABS_API_KEY", "").strip()
    if not key:
        raise SystemExit("ELEVENLABS_API_KEY is not set (put it in .env.local and `set -a; source .env.local`)")
    voice_id = voice or os.environ.get("ELEVENLABS_VOICE_ID", "").strip()
    if not voice_id:
        # resolve a voice by name from the account's voice list
        req = urllib.request.Request("https://api.elevenlabs.io/v1/voices", headers={"xi-api-key": key})
        with urllib.request.urlopen(req, timeout=30) as r:
            voices = json.load(r).get("voices", [])
        want = (os.environ.get("ELEVENLABS_VOICE_NAME") or "Adam").lower()
        match = next((v for v in voices if v.get("name", "").lower() == want), voices[0] if voices else None)
        if not match:
            raise SystemExit("no voices available on this ElevenLabs account")
        voice_id = match["voice_id"]
        print(f"voice: {match.get('name')} ({voice_id})", file=sys.stderr)
    body = json.dumps({
        "text": text,
        "model_id": os.environ.get("ELEVENLABS_MODEL_ID", "eleven_multilingual_v2"),
        "voice_settings": {"stability": 0.45, "similarity_boost": 0.8, "style": 0.35, "use_speaker_boost": True, "speed": rate},
    }).encode()
    req = urllib.request.Request(
        f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}?output_format=mp3_44100_128",
        data=body, method="POST",
        headers={"xi-api-key": key, "content-type": "application/json", "accept": "audio/mpeg"},
    )
    with urllib.request.urlopen(req, timeout=120) as r, open(path, "wb") as f:
        f.write(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default="docs/demo/VOICEOVER-FAST.md")
    ap.add_argument("--out", required=True)
    ap.add_argument("--provider", choices=["elevenlabs", "say"], default="elevenlabs" if os.environ.get("ELEVENLABS_API_KEY") else "say")
    ap.add_argument("--voice")
    ap.add_argument("--rate", type=float, default=1.0)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    ext = "mp3" if a.provider == "elevenlabs" else "aiff"
    for n, text in sections(a.script).items():
        path = os.path.join(a.out, f"narr-{n}.{ext}")
        (elevenlabs if a.provider == "elevenlabs" else say)(text, path, a.voice, a.rate)
        d = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", path], capture_output=True, text=True).stdout.strip()
        print(f"{n}: {float(d):.1f}s  {text[:56]}…")
    print(f"provider={a.provider} → {a.out}")


if __name__ == "__main__":
    main()
