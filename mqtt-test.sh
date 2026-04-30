#!/bin/bash

# Define paths matching your Ubuntu structure
BROKER_DIR="$HOME/mqtt-broker"
PUB_DIR="$HOME/mqtt-publishers"
BROKER_IP="127.0.0.1"

echo "=========================================="
echo " Starting MQTTSec Test Environment"
echo "=========================================="

# Cleanup function to kill all spawned background processes on exit
cleanup() {
    echo ""
    echo "Stopping all MQTT processes..."
    kill $BROKER_PID 2>/dev/null
    kill $BENIGN_PID 2>/dev/null
    kill $ATTACKER_PID 2>/dev/null
    echo "Done."
    exit 0
}

# Catch Ctrl+C and kill background processes cleanly
trap cleanup INT TERM

# 1. Start the broker
echo "[1/3] Starting MQTT Broker..."
cd "$BROKER_DIR" || exit 1
python3 mqttsec_broker.py &
BROKER_PID=$!

# Give the broker a moment to initialize
sleep 2

# 2. Start the 10 Benign publishers
echo "[2/3] Starting Benign Publishers (Clients 0-9)..."
cd "$PUB_DIR" || exit 1
python3 benign_publisher.py --broker "$BROKER_IP" &
BENIGN_PID=$!

# 3. Start the 5 Attacker publishers
echo "[3/3] Starting Attacker Publishers (Clients 10-14)..."
python3 attacker_publisher.py --broker "$BROKER_IP" &
ATTACKER_PID=$!

echo "=========================================="
echo " All services running. Press [Ctrl+C] to stop."
echo "=========================================="

# Wait for the broker to finish (it exits after 300 epochs)
wait $BROKER_PID

# Run cleanup gracefully once broker finishes automatically
cleanup