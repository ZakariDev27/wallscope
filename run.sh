#!/usr/bin/env bash
# Builds the engine if needed and starts the WallScope dashboard.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f src/FirewallDetector.Cli/bin/Release/net8.0/wallscope.dll ]; then
  echo "Building the WallScope engine..."
  dotnet build src/FirewallDetector.Cli -c Release --nologo -v quiet
fi

PYTHON="$(command -v python3 || command -v python)"
PYTHONPATH="$PWD/python${PYTHONPATH:+:$PYTHONPATH}" exec "$PYTHON" -m wallscope serve "$@"
