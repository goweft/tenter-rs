#!/usr/bin/env bash
# Seeds a sample "about to be published" directory so you can reproduce the
# README quickstart output and record docs/demo.gif.
#
#   bash docs/seed-sample.sh [target-dir]    # default: /tmp/tenter-demo
#
# Creates <target>/dist with four files, each tripping a different tenter rule:
#   app.js       -> MAP-002  (sourceMappingURL footer)
#   app.js.map   -> MAP-001  (source map leaks original TypeScript)
#   .env         -> SEC-001 + SEC-002 (sensitive file + embedded AWS keys)
#   index.js     -> clean
#
# Nothing here is a real credential. AKIAIOSFODNN7EXAMPLE / wJalrXUtn... are
# AWS's own publicly documented example keys.
set -euo pipefail

TARGET="${1:-/tmp/tenter-demo}"
DIST="$TARGET/dist"
mkdir -p "$DIST"

# A minified bundle with the classic sourceMappingURL footer.
cat > "$DIST/app.js" <<'EOF'
"use strict";
console.log("hi");
//# sourceMappingURL=app.js.map
EOF

# The source map itself — ships your original source to anyone who downloads.
cat > "$DIST/app.js.map" <<'EOF'
{"version":3,"sources":["../src/app.ts"],"sourcesContent":["secret source"]}
EOF

# A stray .env that should never have made it into the package.
cat > "$DIST/.env" <<'EOF'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

# A perfectly fine file, so the scan isn't all red.
cat > "$DIST/index.js" <<'EOF'
export const version = "1.0.0";
EOF

echo "Seeded $DIST"
