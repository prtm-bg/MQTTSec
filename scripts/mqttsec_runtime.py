#!/usr/bin/env python3
import argparse
import csv
import json
import os
import pickle
import pathlib
import signal
import sys
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt


ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from MQTT_RL import DummyModel, RLenv


ACTION_DECLINE = 0
ACTION_ACCEPT = 1
ACTION_WARN = 2

ACTION_NAME = {
    ACTION_DECLINE: "decline",
    ACTION_ACCEPT: "accept",
    ACTION_WARN: "warn",
}


class MQTTSecRuntime:
    def __init__(self, args):
        self.args = args
        self.model = self._load_model(args.model_path) if args.model_path else None
        policy_model = self.model if self.model is not None else DummyModel()
        self.rl_env = RLenv(policy_model, num_clients=1)
        self.last_seen = {}
        self.running = True

        self.client = mqtt.Client(client_id=args.client_id, clean_session=True)
        if args.username:
            self.client.username_pw_set(args.username, args.password)

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

        self._init_log_file(args.log_file)

    def _load_model(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file does not exist: {path}")

        # Supports simple pickled sklearn-style models with .predict(...)
        with open(path, "rb") as f:
            model = pickle.load(f)

        if not hasattr(model, "predict"):
            raise ValueError("Loaded model has no predict() method")

        return model

    def _init_log_file(self, log_file):
        if os.path.exists(log_file):
            return

        with open(log_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "ts_utc",
                    "source_id",
                    "label",
                    "topic_in",
                    "topic_out",
                    "qos",
                    "timedelta",
                    "window_size",
                    "msg_type",
                    "ml_state",
                    "rule_action",
                    "model_action",
                    "final_action",
                    "payload_bytes",
                ]
            )

    def on_connect(self, client, _userdata, _flags, rc):
        if rc != 0:
            print(f"Connect failed with rc={rc}")
            return

        print(f"Connected to broker. Subscribing to {self.args.ingress_topic}")
        client.subscribe(self.args.ingress_topic, qos=self.args.sub_qos)

    def on_disconnect(self, _client, _userdata, rc):
        if rc != 0 and self.running:
            print(f"Unexpected disconnect rc={rc}")

    def parse_payload(self, msg):
        raw_payload = msg.payload.decode("utf-8", errors="replace")
        payload = {
            "raw": raw_payload,
        }

        try:
            payload.update(json.loads(raw_payload))
        except Exception:
            # Non-JSON payload is still valid for testing.
            pass

        return payload

    def compute_timedelta(self, source_id, topic):
        key = (source_id, topic)
        now = time.monotonic()
        prev = self.last_seen.get(key)
        self.last_seen[key] = now

        if prev is None:
            return self.args.first_msg_timedelta

        return now - prev

    def rule_action(self, msg_type, timedelta_s, window_size):
        return int(
            self.rl_env.check_msg_type(
                msg_type,
                timedelta_s,
                threshold1=self.args.threshold1,
                window_size=window_size,
            )
        )

    def model_action(self, timedelta_s, msg_type, window_size):
        if self.model is None:
            return None

        value = int(self.rl_env.get_state(timedelta_s, msg_type, window_size))

        if value not in (ACTION_DECLINE, ACTION_ACCEPT, ACTION_WARN):
            return ACTION_DECLINE

        return value

    def combine_actions(self, rule_a, model_a):
        mode = self.args.mode

        if mode == "rule":
            return rule_a
        if mode == "model":
            if model_a is None:
                raise RuntimeError("mode=model requires --model-path")
            return model_a

        # hybrid: decline wins, then warn, then accept.
        actions = {rule_a}
        if model_a is not None:
            actions.add(model_a)

        if ACTION_DECLINE in actions:
            return ACTION_DECLINE
        if ACTION_WARN in actions:
            return ACTION_WARN
        return ACTION_ACCEPT

    def map_output_topic(self, in_topic):
        if self.args.clean_topic:
            return self.args.clean_topic

        ingress_prefix = self.args.ingress_prefix
        clean_prefix = self.args.clean_prefix

        if ingress_prefix and in_topic.startswith(ingress_prefix):
            return clean_prefix + in_topic[len(ingress_prefix):]

        return clean_prefix.rstrip("/") + "/" + in_topic.lstrip("/")

    def write_log_row(self, row):
        with open(self.args.log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)

    def on_message(self, client, _userdata, msg):
        payload = self.parse_payload(msg)

        source_id = str(payload.get("source_id", "unknown"))
        label = str(payload.get("label", "unknown"))
        msg_type = str(payload.get("msg_type", "qos1" if msg.qos > 0 else "qos0"))
        window_size = float(payload.get("window_size", self.args.default_window_size))
        timedelta_s = float(payload.get("timedelta", self.compute_timedelta(source_id, msg.topic)))

        ml_state = int(self.rl_env.get_state(timedelta_s, msg_type, window_size))
        rule_a = self.rule_action(msg_type, timedelta_s, window_size)
        model_a = self.model_action(timedelta_s, msg_type, window_size)
        final_a = self.combine_actions(rule_a, model_a)

        out_topic = ""
        if final_a == ACTION_ACCEPT or (final_a == ACTION_WARN and self.args.republish_warn):
            out_topic = self.map_output_topic(msg.topic)
            client.publish(out_topic, payload=msg.payload, qos=min(msg.qos, self.args.pub_qos), retain=False)

        decision_event = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "source_id": source_id,
            "label": label,
            "topic_in": msg.topic,
            "topic_out": out_topic,
            "qos": msg.qos,
            "timedelta": round(timedelta_s, 6),
            "window_size": window_size,
            "msg_type": msg_type,
            "ml_state": ml_state,
            "rule_action": ACTION_NAME[rule_a],
            "model_action": ACTION_NAME[model_a] if model_a is not None else "none",
            "final_action": ACTION_NAME[final_a],
            "payload_bytes": len(msg.payload),
        }

        client.publish(self.args.decision_topic, json.dumps(decision_event), qos=0, retain=False)

        self.write_log_row(
            [
                decision_event["ts_utc"],
                source_id,
                label,
                msg.topic,
                out_topic,
                msg.qos,
                decision_event["timedelta"],
                window_size,
                msg_type,
                ml_state,
                decision_event["rule_action"],
                decision_event["model_action"],
                decision_event["final_action"],
                decision_event["payload_bytes"],
            ]
        )

        print(
            f"[{decision_event['ts_utc']}] src={source_id} label={label} "
            f"in={msg.topic} action={decision_event['final_action']} td={decision_event['timedelta']}"
        )

    def run(self):
        self.client.connect(self.args.broker_host, self.args.broker_port, keepalive=60)
        self.client.loop_start()

        print("MQTTSec runtime is running. Press Ctrl+C to stop.")
        try:
            while self.running:
                time.sleep(0.5)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

    def stop(self):
        self.running = False


def parse_args():
    p = argparse.ArgumentParser(description="MQTTSec runtime service for broker-side filtering")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=1883)
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.add_argument("--client-id", default="mqttsec-runtime")

    p.add_argument("--ingress-topic", default="sensors/raw")
    p.add_argument("--clean-topic", default="sensors/clean")
    p.add_argument("--decision-topic", default="mqttsec/decision")
    p.add_argument("--ingress-prefix", default="")
    p.add_argument("--clean-prefix", default="sensors/clean/")

    p.add_argument("--sub-qos", type=int, default=1)
    p.add_argument("--pub-qos", type=int, default=1)

    p.add_argument("--threshold1", type=float, default=5.0)
    p.add_argument("--default-window-size", type=float, default=2.0)
    p.add_argument("--first-msg-timedelta", type=float, default=0.0)

    p.add_argument("--mode", choices=["rule", "model", "hybrid"], default="rule")
    p.add_argument("--model-path", default="")
    p.add_argument("--republish-warn", action="store_true", default=False)

    p.add_argument("--log-file", default="mqttsec_decisions.csv")
    return p.parse_args()


def main():
    args = parse_args()

    runtime = MQTTSecRuntime(args)

    def _handle_signal(_signum, _frame):
        runtime.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        runtime.run()
    except KeyboardInterrupt:
        runtime.stop()
    except Exception as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
