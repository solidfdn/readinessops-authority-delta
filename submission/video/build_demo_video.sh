#!/usr/bin/env bash
set -euo pipefail

VIDEO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$VIDEO_DIR/../.." && pwd)"
BUILD_DIR="$VIDEO_DIR/build"
OUTPUT="${1:-$REPO_ROOT/dist/readinessops-authority-delta-demo-draft.mp4}"

mkdir -p "$BUILD_DIR" "$(dirname "$OUTPUT")"

render_svg() {
  local source="$1" output="$2"
  inkscape "$source" --export-type=png --export-filename="$output" \
    --export-width=1920 >/dev/null
}

segment() {
  local number="$1" source="$2" duration="$3" filter="$4"
  ffmpeg -hide_banner -loglevel error -y -loop 1 -i "$source" -t "$duration" \
    -vf "$filter,scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=white,fps=30" \
    -an -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p \
    "$BUILD_DIR/segment-$number.mp4"
}

render_svg "$VIDEO_DIR/title.svg" "$BUILD_DIR/title.png"
render_svg "$REPO_ROOT/docs/ARCHITECTURE.svg" "$BUILD_DIR/architecture.png"
render_svg "$VIDEO_DIR/pass.svg" "$BUILD_DIR/pass.png"
render_svg "$VIDEO_DIR/end.svg" "$BUILD_DIR/end.png"

segment 01 "$BUILD_DIR/title.png" 20 "null"
segment 02 "$VIDEO_DIR/live_screens/assessment.png" 35 "null"
segment 03 "$VIDEO_DIR/live_screens/publication-and-authority.png" 35 "crop=970:650:0:0"
segment 04 "$BUILD_DIR/architecture.png" 40 "null"
segment 05 "$VIDEO_DIR/live_screens/execution-allow.png" 50 "crop=793:760:0:470"
segment 06 "$VIDEO_DIR/live_screens/stop-verifying.png" 45 "null"
segment 07 "$VIDEO_DIR/live_screens/suspension-confirmed.png" 35 "null"
segment 08 "$BUILD_DIR/pass.png" 20 "null"
segment 09 "$BUILD_DIR/end.png" 5 "null"

LIST="$BUILD_DIR/segments.txt"
: > "$LIST"
for file in "$BUILD_DIR"/segment-*.mp4; do
  printf "file '%s'\n" "$file" >> "$LIST"
done

ffmpeg -hide_banner -loglevel error -y -f concat -safe 0 -i "$LIST" \
  -f lavfi -i anullsrc=r=48000:cl=stereo \
  -vf "subtitles=$VIDEO_DIR/captions_en.srt:force_style='FontName=Arial,FontSize=16,PrimaryColour=&H00FFFFFF,OutlineColour=&H00203850,BorderStyle=3,BackColour=&HCC071D3A,Outline=1,Shadow=0,MarginV=30,Alignment=2'" \
  -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
  -c:a aac -b:a 128k -shortest -movflags +faststart "$OUTPUT"

ffprobe -v error -show_entries format=duration,size \
  -of default=noprint_wrappers=1 "$OUTPUT"
