#!/usr/bin/env python3
import argparse
import json
import random
import signal
import string
import time

import paho.mqtt.client as mqtt


def random_value():
    return round(random.uniform(20.0, 30.0), 3)


def random_text(n=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def parse_args():
    p = argparse.ArgumentParser(description="Normal MQTT publisher")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=1883)
    p.add_argument("--topic", default="sensors/raw")
    p.add_argument("--qos", type=int, default=1)
    p.add_argument("--source-id", default="pub_normal")
    p.add_argument("--interval-min", type=float, default=1.0)
    p.add_argument("--interval-max", type=float, default=2.0)
    p.add_argument("--window-size", type=float, default=2.0)
    p.add_argument("--msg-type", default="qos1")
    p.add_argument("--count", type=int, default=0, help="0 means infinite")
    return p.parse_args()


def main():
    args = parse_args()
    client = mqtt.Client(client_id=f"{args.source_id}_client", clean_session=True)
    client.connect(args.broker_host, args.broker_port, keepalive=60)
    client.loop_start()

    running = True

    def _stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    i = 0
    while running:
        i += 1
        payload = {
            "source_id": args.source_id,
            "label": "normal",
            "msg_type": args.msg_type,
            "window_size": args.window_size,
            "seq": i,
            "sensor": "temp",
            "value": random_value(),
            "nonce": random_text(8),
            "ts": time.time(),
        }

        client.publish(args.topic, json.dumps(payload), qos=args.qos, retain=False)
        print(f"published normal seq={i}")

        if args.count > 0 and i >= args.count:
            break

        sleep_s = random.uniform(args.interval_min, args.interval_max)
        time.sleep(max(sleep_s, 0.01))

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
