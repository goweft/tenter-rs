# tenter-rs demo — record with:  vhs docs/demo.tape   (writes docs/demo.gif)
#
# Requirements:
#   - vhs       https://github.com/charmbracelet/vhs
#   - tenter    on PATH (see the README install section)
#
# Reproducible: the sample is seeded fresh by docs/seed-sample.sh, so re-running
# this tape always produces the same scan. Run from the repo root.
#
# Fallback without vhs (asciinema):
#   bash docs/seed-sample.sh /tmp/tenter-demo
#   asciinema rec -c 'cd /tmp/tenter-demo && tenter scan dist' docs/demo.cast

Output docs/demo.gif

Set Shell bash
Set FontSize 18
Set Width 1100
Set Height 760
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 45ms

# --- seed the sample off-camera so the recording is deterministic ---
Hide
Type "bash docs/seed-sample.sh /tmp/tenter-demo >/dev/null && cd /tmp/tenter-demo && clear"
Enter
Sleep 800ms
Show

# --- on-camera: what's about to ship, then the scan that blocks it ---
Type "ls -A dist"
Sleep 400ms
Enter
Sleep 1500ms

Type "tenter scan dist"
Sleep 500ms
Enter
Sleep 4500ms
