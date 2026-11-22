# benign_publisher.py
# Runs on RPi 4 #1.
# Simulates 10 benign clients (IDs 0-9).
#
# Every client runs in its own thread with its own MQTT connection and its
# own send loop, so the time delta the broker measures for a client is that
# client's real sending interval (Sec. 7: "each running as a separate client
# process"). Previously all ten IDs were sent round-robin from one loop, so
# each ID reached the broker only about every 650 ms instead of 35-80 ms.
#
# Usage:
#   pip3 install paho-mqtt --break-system-packages
#   python3 benign_publisher.py --broker 192.168.1.100
#
# Topic format : mqttsec/c{id}/{msg_type}
# Payload JSON : {"cid": id, "is_attack": 0, "data": "..."}

import paho.mqtt.client as mqtt
import time
import random
import json
import argparse
import socket
import threading

# Configuration
BENIGN_CLIENT_IDS = list(range(0, 10))   # clients 0-9 are benign

# Safe parameter ranges (stay inside paper's θ thresholds)
# θ1min=8B, θ1max=650B, θ2min=5ms, θ2max=55ms, θ2avg=30ms

QOS0_PAYLOAD_BYTES  = (4, 8)       # small payload, well under θ1min
QOS0_SLEEP_MS       = (35, 60)     # time delta > θ2avg (30ms) → accept

QOS1_PAYLOAD_BYTES  = (4, 8)       # small payload
QOS1_SLEEP_MS       = (60, 80)     # time delta > θ2max (55ms) → accept

CONNECT_PAYLOAD_BYTES = (4, 8)
CONNECT_SLEEP_MS      = (60, 80)

# Message type assigned per client
MSG_TYPE_MAP = {
    0: 'qos0',   1: 'qos0',   2: 'qos0',
    3: 'qos1',   4: 'qos1',   5: 'qos1',
    6: 'qos1',
    7: 'connect', 8: 'connect', 9: 'connect'
}

BASE_SEED = 1


def create_mqtt_client(client_id):
    """
    Use callback API v2 when available to avoid deprecation warnings,
    while staying compatible with older paho-mqtt releases.
    """
    try:
        return mqtt.Client(
            client_id=client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2
        )
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id)


def make_payload(cid, target_bytes, is_attack=0):
    """
    Build a JSON payload whose total encoded length is ~target_bytes.
    The 'data' field is padded to reach the target size.
    """
    base    = json.dumps({"cid": cid, "is_attack": is_attack, "data": ""})
    padding = max(0, target_bytes - len(base.encode()))
    return json.dumps({
        "cid":       cid,
        "is_attack": is_attack,
        "data":      "B" * padding
    }).encode()


def next_message(msg_type, rng):
    """Return (payload_len, sleep_seconds) for one message of this type."""
    if msg_type == 'qos0':
        plen       = rng.randint(*QOS0_PAYLOAD_BYTES)
        base_sleep = rng.randint(*QOS0_SLEEP_MS)
        sleep      = (base_sleep + abs(rng.gauss(5, 15))) / 1000.0
    elif msg_type == 'qos1':
        plen       = rng.randint(*QOS1_PAYLOAD_BYTES)
        base_sleep = rng.randint(*QOS1_SLEEP_MS)
        sleep      = (base_sleep + abs(rng.gauss(5, 20))) / 1000.0
    else:   # connect
        plen       = rng.randint(*CONNECT_PAYLOAD_BYTES)
        base_sleep = rng.randint(*CONNECT_SLEEP_MS)
        sleep      = (base_sleep + abs(rng.gauss(5, 20))) / 1000.0
    return plen, sleep


class BenignClient(threading.Thread):
    """One benign client: its own MQTT connection and its own send loop."""

    def __init__(self, cid, broker_ip, broker_port, stop_event, verbose):
        super().__init__(daemon=True, name=f"benign_c{cid}")
        self.cid         = cid
        self.msg_type    = MSG_TYPE_MAP[cid]
        self.broker_ip   = broker_ip
        self.broker_port = broker_port
        self.stop_event  = stop_event
        self.verbose     = verbose
        self.rng         = random.Random(BASE_SEED * 100 + cid)
        self.client      = create_mqtt_client(f"benign_c{cid}_rpi4_1")

    def run(self):
        try:
            self.client.connect(self.broker_ip, self.broker_port, keepalive=60)
        except ConnectionRefusedError:
            print(f"[Benign] c{self.cid} connection refused by "
                  f"{self.broker_ip}:{self.broker_port}")
            return
        except socket.gaierror as e:
            print(f"[Benign] c{self.cid} invalid broker address "
                  f"'{self.broker_ip}': {e}")
            return
        except OSError as e:
            print(f"[Benign] c{self.cid} could not connect to "
                  f"{self.broker_ip}:{self.broker_port} ({e})")
            return

        self.client.loop_start()
        msg_type = self.msg_type
        topic    = f"mqttsec/c{self.cid}/{msg_type}"
        qos      = 0 if msg_type == 'qos0' else 1
        # Single write (text + newline) so lines from different threads don't merge
        print(f"[Benign] c{self.cid:2d} connected | type={msg_type}\n", end="")

        try:
            while not self.stop_event.is_set():
                plen, sleep = next_message(msg_type, self.rng)
                payload = make_payload(self.cid, plen, is_attack=0)
                try:
                    result = self.client.publish(topic, payload, qos=qos)
                    if result.rc != mqtt.MQTT_ERR_SUCCESS:
                        print(f"[Benign] c{self.cid} publish failed: {result.rc}")
                    elif self.verbose:
                        print(f"[Benign] c{self.cid:2d} | {msg_type:8s} | "
                              f"{len(payload):4d}B | sleep={sleep*1000:.0f}ms")
                except Exception as e:
                    print(f"[Benign] c{self.cid} error: {e}")

                self.stop_event.wait(sleep)
        finally:
            self.client.loop_stop()
            self.client.disconnect()


def run_benign_publisher(broker_ip, broker_port=1883, verbose=False):
    stop_event = threading.Event()
    clients = [BenignClient(cid, broker_ip, broker_port, stop_event, verbose)
               for cid in BENIGN_CLIENT_IDS]

    print(f"[Benign] Starting clients {BENIGN_CLIENT_IDS} "
          f"(one connection and send loop per client)")
    for c in clients:
        c.start()

    try:
        while any(c.is_alive() for c in clients):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[Benign] Stopping...")
    finally:
        stop_event.set()
        for c in clients:
            c.join(timeout=2.0)
        print("[Benign] Stopped.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Benign MQTT Publisher")
    parser.add_argument('--broker', default='192.168.1.100',
                        help='Broker IP (RPi 5). Default: 192.168.1.100')
    parser.add_argument('--port',   default=1883, type=int,
                        help='Broker port. Default: 1883')
    parser.add_argument('--verbose', action='store_true',
                        help='Print every published message')
    args = parser.parse_args()

    run_benign_publisher(args.broker, args.port, args.verbose)
