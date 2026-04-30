# benign_publisher.py
# Runs on RPi 4 #1.
# Simulates 10 benign clients (IDs 0-9).
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


def run_benign_publisher(broker_ip, broker_port=1883):
    client = create_mqtt_client("benign_publisher_rpi4_1")
    try:
        client.connect(broker_ip, broker_port, keepalive=60)
    except ConnectionRefusedError:
        print(f"[Benign] Connection refused by {broker_ip}:{broker_port}")
        print("[Benign] Ensure Mosquitto is running and listening on 1883.")
        return
    except socket.gaierror as e:
        print(f"[Benign] Invalid broker address '{broker_ip}': {e}")
        return
    except OSError as e:
        print(f"[Benign] Could not connect to {broker_ip}:{broker_port} ({e})")
        return

    client.loop_start()
    print(f"[Benign] Connected to {broker_ip}:{broker_port}")
    print(f"[Benign] Simulating clients {BENIGN_CLIENT_IDS}")

    try:
        while True:
            for cid in BENIGN_CLIENT_IDS:
                msg_type = MSG_TYPE_MAP[cid]

                if msg_type == 'qos0':
                    plen  = random.randint(*QOS0_PAYLOAD_BYTES)
                    sleep = random.randint(*QOS0_SLEEP_MS) / 1000.0

                elif msg_type == 'qos1':
                    plen  = random.randint(*QOS1_PAYLOAD_BYTES)
                    sleep = random.randint(*QOS1_SLEEP_MS) / 1000.0

                else:   # connect
                    plen  = random.randint(*CONNECT_PAYLOAD_BYTES)
                    sleep = random.randint(*CONNECT_SLEEP_MS) / 1000.0

                topic   = f"mqttsec/c{cid}/{msg_type}"
                payload = make_payload(cid, plen, is_attack=0)
                qos     = 0 if msg_type == 'qos0' else 1

                result = client.publish(topic, payload, qos=qos)

                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    print(f"[Benign] c{cid:2d} | {msg_type:8s} | "
                          f"{len(payload):4d}B | sleep={sleep*1000:.0f}ms")
                else:
                    print(f"[Benign] c{cid} publish failed: {result.rc}")

                time.sleep(sleep)

    except KeyboardInterrupt:
        print("\n[Benign] Stopped.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Benign MQTT Publisher")
    parser.add_argument('--broker', default='192.168.1.100',
                        help='Broker IP (RPi 5). Default: 192.168.1.100')
    parser.add_argument('--port',   default=1883, type=int,
                        help='Broker port. Default: 1883')
    args = parser.parse_args()

    random.seed(1)
    run_benign_publisher(args.broker, args.port)
