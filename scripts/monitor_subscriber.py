#!/usr/bin/env python3
import argparse
import json
import signal
import time
from collections import Counter

import paho.mqtt.client as mqtt


class Monitor:
    def __init__(self, args):
        self.args = args
        self.counter = Counter()
        self.last_print = time.time()
        self.running = True

        self.client = mqtt.Client(client_id=args.client_id, clean_session=True)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def on_connect(self, client, _userdata, _flags, rc):
        if rc != 0:
            print(f"Connect failed rc={rc}")
            return

        print("Connected. Subscribing to monitor topics...")
        client.subscribe(self.args.raw_topic, qos=1)
        client.subscribe(self.args.clean_topic, qos=1)
        client.subscribe(self.args.decision_topic, qos=0)

    def on_message(self, _client, _userdata, msg):
        self.counter[f"topic:{msg.topic}"] += 1

        if msg.topic == self.args.decision_topic:
            try:
                event = json.loads(msg.payload.decode("utf-8", errors="replace"))
                action = event.get("final_action", "unknown")
                label = event.get("label", "unknown")
                self.counter[f"action:{action}"] += 1
                self.counter[f"label:{label}"] += 1
            except Exception:
                self.counter["decision_parse_errors"] += 1

        now = time.time()
        if now - self.last_print >= self.args.print_every:
            self.print_stats()
            self.last_print = now

    def print_stats(self):
        print("----- Monitor Stats -----")
        for key in sorted(self.counter):
            print(f"{key}: {self.counter[key]}")

    def run(self):
        self.client.connect(self.args.broker_host, self.args.broker_port, keepalive=60)
        self.client.loop_start()
        print("Monitoring started. Press Ctrl+C to stop.")

        try:
            while self.running:
                time.sleep(0.5)
        finally:
            self.print_stats()
            self.client.loop_stop()
            self.client.disconnect()


def parse_args():
    p = argparse.ArgumentParser(description="MQTT monitor for raw/clean/decision topics")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=1883)
    p.add_argument("--client-id", default="mqtt-monitor")
    p.add_argument("--raw-topic", default="sensors/raw")
    p.add_argument("--clean-topic", default="sensors/clean")
    p.add_argument("--decision-topic", default="mqttsec/decision")
    p.add_argument("--print-every", type=float, default=5.0)
    return p.parse_args()


def main():
    args = parse_args()
    monitor = Monitor(args)

    def _stop(_signum, _frame):
        monitor.running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    monitor.run()


if __name__ == "__main__":
    main()
