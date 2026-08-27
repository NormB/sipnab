#!/usr/bin/env bash
# Generate the caller and callee media fixtures as real speech.
#
# A tone proves the two legs differ. It cannot show whether a CALL was
# captured, because nobody can tell a well-recorded sine from a badly recorded
# one. Two clearly different voices saying different things make a captured
# call audible as a call: if you can hear both halves of the conversation, the
# capture worked.
#
# A male caller and a female callee, counting in opposite directions. A stereo
# export whose channels carry one leg twice is a real failure mode, and two
# similar voices would hide it -- a listener should know within a second which
# side they are hearing, and whether they are hearing both.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
VOICES="${PIPER_VOICES:-$HOME/Development/voxcortex/models/piper-voices}"
CALLER_VOICE="${CALLER_VOICE:-en_US-ryan-medium}"      # male
CALLEE_VOICE="${CALLEE_VOICE:-en_US-amy-medium}"       # female
SECONDS_TARGET="${SPEECH_SECONDS:-90}"

CALLER_TEXT="${CALLER_TEXT:-Hello, this is the calling party speaking. This call is a capture test for the recording pipeline. I will count slowly so you can hear which side you are listening to. One. Two. Three. Four. Five. Six. Seven. Eight. Nine. Ten.}"
CALLEE_TEXT="${CALLEE_TEXT:-Good morning, this is the answering party. I can hear you clearly on my end of the call. Now I will count as well, so the two directions are easy to tell apart. Ten. Nine. Eight. Seven. Six. Five. Four. Three. Two. One.}"

for v in "$CALLER_VOICE" "$CALLEE_VOICE"; do
    [ -f "$VOICES/$v.onnx" ] || {
        echo "missing voice: $VOICES/$v.onnx" >&2
        echo "set PIPER_VOICES, or pick from: $(ls "$VOICES" 2>/dev/null | grep -o '^[a-z_A-Z-]*medium' | tr '\n' ' ')" >&2
        exit 1
    }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

synth() {  # synth <voice> <text> <out.wav>
    python3 - "$VOICES/$1.onnx" "$2" "$3" <<'PY' 2>/dev/null
import sys, wave
from piper import PiperVoice
model, text, out = sys.argv[1], sys.argv[2], sys.argv[3]
voice = PiperVoice.load(model)
with wave.open(out, "wb") as w:
    voice.synthesize_wav(text, w)
PY
}

# Repeat the script until it fills the call. A fixture shorter than the call
# leaves the far end silent for most of the recording, which reads as a
# one-way call rather than as a short sample.
build() {  # build <voice> <text> <out.wav>
    synth "$1" "$2" "$tmp/one.wav"
    local dur reps
    dur="$(soxi -D "$tmp/one.wav")"
    reps="$(python3 -c "import math,sys; print(max(1, math.ceil($SECONDS_TARGET / float(sys.argv[1]))))" "$dur")"
    local args=()
    for _ in $(seq "$reps"); do args+=("$tmp/one.wav"); done
    sox "${args[@]}" "$tmp/long.wav"
    sox "$tmp/long.wav" "$3" trim 0 "$SECONDS_TARGET"
    rm -f "$tmp/one.wav" "$tmp/long.wav"
}

echo "== caller: $CALLER_VOICE"
build "$CALLER_VOICE" "$CALLER_TEXT" "$tmp/caller.wav"
echo "== callee: $CALLEE_VOICE"
build "$CALLEE_VOICE" "$CALLEE_TEXT" "$tmp/callee.wav"

python3 "$HERE/scripts/make-pcma-pcap.py" "$HERE/sipp/scenarios/g711a_caller.pcap" \
    --from-wav "$tmp/caller.wav" --ssrc 0x0CA11E12
python3 "$HERE/scripts/make-pcma-pcap.py" "$HERE/sipp/scenarios/g711a_answer.pcap" \
    --from-wav "$tmp/callee.wav" --ssrc 0x5AFE1234
