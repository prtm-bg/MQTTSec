# attacker_publisher.py
# Runs on RPi 4 #2.
# Simulates 5 attacker clients (IDs 10-14).
# Cycles through the 3 attack types from the paper (Section 4.1).
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


def run_attacker_publisher(broker_ip, broker_port=1883):
    client = create_mqtt_client("attacker_publisher_rpi4_2")
    try:
        client.connect(broker_ip, broker_port, keepalive=60)
    except ConnectionRefusedError:
        print(f"[Attacker] Connection refused by {broker_ip}:{broker_port}")
        print("[Attacker] Ensure Mosquitto is running and listening on 1883.")
        return
    except socket.gaierror as e:
        print(f"[Attacker] Invalid broker address '{broker_ip}': {e}")
        return
    except OSError as e:
        print(f"[Attacker] Could not connect to {broker_ip}:{broker_port} ({e})")
        return

    client.loop_start()
    print(f"[Attacker] Connected to {broker_ip}:{broker_port}")
    print(f"[Attacker] Simulating attack clients {ATTACK_CLIENT_IDS}")
    print(f"[Attacker] Attack types: {ATTACK_TYPE_MAP}")

    try:
        while True:
            for cid in ATTACK_CLIENT_IDS:
                attack_type = ATTACK_TYPE_MAP[cid]

                if attack_type == 'connect':
                    # Attack 1: CONNECT flooding
                    plen  = random.randint(*CONNECT_FLOOD_PAYLOAD)
                    sleep = random.randint(*CONNECT_FLOOD_SLEEP) / 1000.0
                    msg_t = 'connect'

                elif attack_type == 'qos0':
                    # Attack 2: Fast flooding
                    plen  = random.randint(*FAST_FLOOD_PAYLOAD)
                    sleep = random.randint(*FAST_FLOOD_SLEEP) / 1000.0
                    msg_t = 'qos0'

                else:
                    # Attack 3: Heavy flooding (qos1)
                    plen  = random.randint(*HEAVY_FLOOD_PAYLOAD)
                    sleep = random.randint(*HEAVY_FLOOD_SLEEP) / 1000.0
                    msg_t = 'qos1'

                topic   = f"mqttsec/c{cid}/{msg_t}"
                payload = make_payload(cid, plen, is_attack=1)
                qos     = 0 if msg_t == 'qos0' else 1

                try:
                    result = client.publish(topic, payload, qos=qos)
                    if result.rc == mqtt.MQTT_ERR_SUCCESS:
                        print(f"[Attacker] c{cid:2d} | {msg_t:8s} | "
                              f"{len(payload):5d}B | sleep={sleep*1000:.0f}ms")
                    else:
                        print(f"[Attacker] c{cid} publish failed: {result.rc}")
                except Exception as e:
                    print(f"[Attacker] c{cid} error: {e}")

                time.sleep(sleep)

    except KeyboardInterrupt:
        print("\n[Attacker] Stopped.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Attacker MQTT Publisher")
    parser.add_argument('--broker', default='192.168.1.100',
                        help='Broker IP (RPi 5). Default: 192.168.1.100')
    parser.add_argument('--port',   default=1883, type=int,
                        help='Broker port. Default: 1883')
    args = parser.parse_args()

    random.seed(2)
    run_attacker_publisher(args.broker, args.port)
