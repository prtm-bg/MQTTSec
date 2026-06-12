#!/bin/bash

# The TUI python script handles paths, process spawning, and clean up.
# We just need to launch the TUI.

echo "=========================================="
echo " Starting MQTTSec Test Environment TUI"
echo "=========================================="

# Auto-detect folder paths based on local macOS or Ubuntu SSH layout
if [ -f "mqtt_tui.py" ]; then
    python3 mqtt_tui.py
else
    # Assume it's located in the broker directory based on previous Ubuntu context
    cd "$HOME/mqtt-broker" || exit 1
    python3 mqtt_tui.py
fi