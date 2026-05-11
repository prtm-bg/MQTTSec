# mqttsec_broker.py
# Runs on RPi 5 alongside Mosquitto.
#
# Usage:
#   pip3 install paho-mqtt numpy scikit-learn matplotlib --break-system-packages
#   python3 mqttsec_broker.py
#
# Requires: rf_model.pkl in the same directory (produced by train_rf.py)

import random
import numpy as np
import pickle
import json
import time
import threading
import csv
import os
import matplotlib
matplotlib.use('Agg')   # no display needed on RPi
import matplotlib.pyplot as plt
import paho.mqtt.client as mqtt
from sklearn.ensemble import RandomForestClassifier

# PAPER TABLE 2 - CONSTANTS
THETA1_MIN   = 8       # bytes  — min safe payload length
THETA1_MAX   = 650     # bytes  — max safe payload length
THETA2_MIN   = 5.0     # ms     — min safe time delta
THETA2_MAX   = 55.0    # ms     — max safe time delta
THETA2_AVG   = 30.0    # ms     — average threshold used for QoS0 (Eq.6)

TAU_EPOCH    = 18.0    # return threshold for epoch-level decision (Eq.9)
EPSILON_R    = 0.1     # residual epsilon (Table 2)
GAMMA        = 0.9     # discount factor (Eq.10)
N_EPISODES   = 10      # episodes per epoch (Table 2)
N_EPOCHS     = 60      # total epochs to run (author instruction)
RETRAIN_INT  = 15      # epochs between ML retraining (Table 2 / author)
BAN_DURATION = 2       # suspension duration in epochs (Δ)
NUM_CLIENTS  = 15      # 10 benign + 5 attacker

BROKER_IP    = "localhost"   # monitor runs on the broker itself
BROKER_PORT  = 1883
LOG_FILE     = "mqttsec_log.csv"
RESULTS_FILE = "mqttsec_results.txt"

# Episode collection window — broker waits this long to gather one
# message from each client before running an episode
EPISODE_WINDOW_SEC = 2.0


# RF MODEL WRAPPER
class RFModel:
    """
    Wraps the trained RandomForest.
    - predict()        : classifies a single message → state 0 or 1
    - compute_error()  : measures error on a batch (end of each episode)
    - retrain()        : retrains on accumulated traffic_buffer
    """

    def __init__(self, model_path="rf_model.pkl"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"RF model not found: {model_path}\n"
                "Run train_rf.py first, then copy rf_model.pkl here."
            )
        with open(model_path, "rb") as f:
            self.rf = pickle.load(f)
        self.last_error = 0.0
        print(f"[RFModel] Loaded from {model_path}")

    def predict(self, payload_len, timedelta_ms):
        """
        Classify one message.
        Returns state: 0 = benign, 1 = attack
        Features match Figure 8: [mqtt.len, tcp.time_delta]
        """
        X = np.array([[float(payload_len), float(timedelta_ms)]])
        return int(self.rf.predict(X)[0])

    def compute_error(self, features_list, labels_list):
        """
        Compute classification error on this episode's batch.
        Called at end of each episode → feeds into epsilon update.
        features_list : [[payload_len, timedelta_ms], ...]
        labels_list   : [0/1, ...]  (ground truth from publisher)
        """
        if not features_list:
            return self.last_error
        X      = np.array(features_list, dtype=np.float32)
        y_true = np.array(labels_list,   dtype=int)
        y_pred = self.rf.predict(X)
        self.last_error = float(np.mean(y_pred != y_true))
        return self.last_error

    def retrain(self, traffic_buffer):
        """
        Retrain RF on accumulated (features, label) pairs.
        Called every RETRAIN_INT epochs.
        Returns new classification error on held-out 20%.
        """
        if len(traffic_buffer) < 20:
            print("[RFModel] Not enough data for retraining — skipping.")
            return self.last_error

        X = np.array([t[0] for t in traffic_buffer], dtype=np.float32)
        y = np.array([t[1] for t in traffic_buffer], dtype=int)

        # 80/20 split — paper Section 6.3
        split      = int(0.8 * len(X))
        X_tr, X_te = X[:split], X[split:]
        y_tr, y_te = y[:split], y[split:]

        self.rf.fit(X_tr, y_tr)
        y_pred      = self.rf.predict(X_te)
        error       = float(np.mean(y_pred != y_te))
        self.last_error = error

        print(f"[RFModel] Retrained | train={len(X_tr)} test={len(X_te)} "
              f"error={error:.4f} acc={(1-error)*100:.2f}%")
        return error

    def get_last_error(self):
        return self.last_error


# RL ENVIRONMENT (complete - author's code + all fixes)
class RLenv:
    """
    Full MQTTSec RL environment.

    Episode-level : accepts / warns / declines individual messages (Eq.5, 6)
    Epoch-level   : continue or suspend clients (Eq.9)
    ε-greedy      : stochastic epoch actions (Eq.11)
    ε update      : driven by real RF classification error (Eq.12)
    Retraining    : RF retrained every RETRAIN_INT epochs
    """

    def __init__(self, model, num_clients=NUM_CLIENTS):
        self.model       = model
        self.num_clients = num_clients
        self.gamma       = GAMMA
        self.tau_epoch   = TAU_EPOCH
        self.epsilon_r   = EPSILON_R
        self.epsilon     = EPSILON_R
        self.ban_duration = BAN_DURATION

        # Per-client reward buffer — reset each epoch
        self.reward_buffer = {i: [] for i in range(num_clients)}

        # Running total return across all epochs (for final report)
        self.return1 = [0.0 for _ in range(num_clients)]

        # Suspension registry  {client_id: epochs_left_in_ban}
        self.suspended = {}

        # Episode / epoch counters
        self.episode_count       = 0
        self.epoch_count         = 0
        self.episodes_per_epoch  = N_EPISODES

        # Classification error (updated each episode from real RF)
        self.last_classification_error = 0.0

        # Traffic buffer for periodic retraining
        # Stores ([payload_len, timedelta_ms], true_label) tuples
        self.traffic_buffer = []

        # History for plotting
        self.epoch_epsilon_history = []
        self.epoch_error_history   = []
        self.suspension_history    = {}   # epoch → list of suspended client IDs

    # STATE

    def get_state(self, payload_len, timedelta_ms):
        """RF classifies traffic → 0 (benign) or 1 (attack)"""
        return self.model.predict(payload_len, timedelta_ms)

    # EPISODE-LEVEL POLICY (Equations 5 and 6)

    def check_msg_type(self, msg_type, timedelta_ms, payload_len, ml_state=0):
        """
        Episode-level action policy.

        QoS0  → Equation 6 (time delta only)
        QoS1 / CONNECT → Equation 5 (payload length + time delta)

        ml_state: 0=benign, 1=attack  (from RF)
        If RF says attack AND features are in borderline warn zone,
        escalate warn → decline (conservative behaviour).
        """
        if msg_type == 'qos0':
            # Eq.6 — only tδ matters for fast flooding detection
            if timedelta_ms >= THETA2_AVG:
                return self.send_message_accept()
            else:
                return self.send_message_decline()

        elif msg_type in ['qos1', 'connect']:
            # Eq.5 — both payload length (L) and tδ matter
            if payload_len <= THETA1_MIN and timedelta_ms >= THETA2_MAX:
                # Small payload, slow rate → clearly safe
                return self.send_message_accept()

            elif (THETA1_MIN < payload_len <= THETA1_MAX and
                  THETA2_MIN <= timedelta_ms < THETA2_MAX):
                # Borderline — warn normally, but if RF also flags it → decline
                if ml_state == 1:
                    return self.send_message_decline()
                return self.send_message_warn()

            else:
                # Large payload OR very fast rate → decline
                return self.send_message_decline()

        return self.send_message_decline()

    # REWARD SIGNALS

    def send_message_accept(self):  return 1
    def send_message_warn(self):    return 2
    def send_message_decline(self): return 0

    def reward_return(self, actions):
        labels = {1: "Accept  +1", 2: "Warn    +2", 0: "Decline  0"}
        rewards = []
        for a in actions:
            print(f"    Action: {labels.get(a, '?')}")
            rewards.append(a)   # reward == action value (1, 2, or 0)
        return rewards

    # DISCOUNTED RETURN (Equation 10)

    def compute_discounted_return(self, rewards):
        return sum((self.gamma ** k) * r for k, r in enumerate(rewards))

    # EPSILON UPDATE (Equation 12)

    def update_epsilon(self, classification_error):
        """ε = εr + Yn/2   (Eq. 12)"""
        self.epsilon = self.epsilon_r + classification_error / 2.0
        self.epsilon = min(self.epsilon, 1.0)

    # EPOCH-LEVEL ACTION (Equation 9 + Equation 11)

    def epoch_action(self, client_id, G):
        """
        ε-greedy decision per client.
        With prob ε   → explore  (random Continue/Suspend)
        With prob 1-ε → exploit  (G vs τE)
        """
        if random.random() < self.epsilon:
            decision = random.choice(['Continue', 'Suspend'])
            tag = "EXPLORE"
        else:
            decision = 'Continue' if G > self.tau_epoch else 'Suspend'
            tag = "EXPLOIT"

        print(f"    [{tag}] Client {client_id:2d} → {decision:8s} "
              f"(G={G:.3f}, τ={self.tau_epoch}, ε={self.epsilon:.3f})")
        return decision == 'Continue'

    # SUSPENSION MANAGEMENT

    def suspend_client(self, client_id):
        self.reward_buffer[client_id] = []
        self.suspended[client_id]     = self.ban_duration
        print(f"    *** Client {client_id} SUSPENDED "
              f"for {self.ban_duration} epoch(s) ***")

    def decrement_bans(self):
        to_reinstate = [
            cid for cid, rem in self.suspended.items()
            if rem - 1 <= 0
        ]
        for cid in list(self.suspended):
            self.suspended[cid] -= 1
        for cid in to_reinstate:
            del self.suspended[cid]
            print(f"    Client {cid} reinstated after ban.")

    def is_suspended(self, client_id):
        return client_id in self.suspended

    # EPISODE LOOP

    def run_episode(self, clients):
        """
        Process one episode.
        clients: list of dicts with keys:
            id, msg_type, timedelta_ms, payload_len, true_label
        Returns: (rewards list, epoch_results dict or None)
        """
        ep_num = self.episode_count + 1
        ek_num = self.epoch_count + 1
        print(f"\n  {'─'*55}")
        print(f"  Episode {ep_num}/{N_EPISODES}  |  Epoch {ek_num}/{N_EPOCHS}")
        print(f"  {'─'*55}")

        actions         = []
        active_ids      = []
        episode_feats   = []
        episode_labels  = []

        for client in clients:
            cid        = client['id']
            msg_type   = client['msg_type']
            td_ms      = client['timedelta_ms']
            plen       = client['payload_len']
            true_label = client.get('true_label', 0)

            if self.is_suspended(cid):
                print(f"    Client {cid:2d} SUSPENDED — skipped.")
                continue

            # Get ML state from RF
            ml_state = self.get_state(plen, td_ms)
            ml_label = "ATTACK" if ml_state == 1 else "benign"

            print(f"    Client {cid:2d} | {msg_type:8s} | "
                  f"len={plen:5d}B | td={td_ms:7.1f}ms | RF={ml_label}")

            # Accumulate for error calculation and retraining
            episode_feats.append([float(plen), float(td_ms)])
            episode_labels.append(true_label)
            self.traffic_buffer.append(([float(plen), float(td_ms)], true_label))

            # Apply episode-level policy
            action = self.check_msg_type(msg_type, td_ms, plen, ml_state=ml_state)
            actions.append(action)
            active_ids.append(cid)

        rewards = self.reward_return(actions)

        # Store rewards per client
        for cid, r in zip(active_ids, rewards):
            self.reward_buffer[cid].append(r)
            self.return1[cid] += r

        # Update classification error from real RF (author instruction 1)
        if episode_feats:
            self.last_classification_error = self.model.compute_error(
                episode_feats, episode_labels
            )
            print(f"\n    RF classification error this episode: "
                  f"{self.last_classification_error:.4f}")

        self.episode_count += 1

        # Check epoch boundary
        epoch_results = None
        if self.episode_count >= self.episodes_per_epoch:
            epoch_results = self._run_epoch_evaluation(clients)
            self.episode_count = 0

        return rewards, epoch_results

    # EPOCH EVALUATION

    def _run_epoch_evaluation(self, clients):
        """
        Called automatically at end of every N_EPISODES episodes.
        1. Optionally retrain RF  (every RETRAIN_INT epochs)
        2. Update epsilon
        3. ε-greedy continue/suspend per client
        4. Reset reward buffers
        5. Decrement suspension timers
        """
        self.epoch_count += 1
        print(f"\n  {'#'*55}")
        print(f"  EPOCH {self.epoch_count} / {N_EPOCHS}  —  EVALUATION")
        print(f"  Last classification error: "
              f"{self.last_classification_error:.4f}")
        print(f"  {'#'*55}")

        # Author instruction 3: retrain every 15 epochs
        if self.epoch_count % RETRAIN_INT == 0:
            print(f"\n  [RETRAIN] Epoch {self.epoch_count} "
                  f"— retraining RF on {len(self.traffic_buffer)} samples...")
            new_error = self.model.retrain(self.traffic_buffer)
            self.last_classification_error = new_error
            self.traffic_buffer = []   # clear buffer after retraining

        # Update epsilon (Eq.12)
        self.update_epsilon(self.last_classification_error)
        print(f"\n  Updated ε = {self.epsilon:.4f}  "
              f"(εr={self.epsilon_r}, err={self.last_classification_error:.4f})")

        # Record for plotting
        self.epoch_epsilon_history.append(self.epsilon)
        self.epoch_error_history.append(self.last_classification_error)

        epoch_results   = {}
        suspended_this  = []

        print("\n  Client decisions:")
        for client in clients:
            cid = client['id']

            if self.is_suspended(cid):
                epoch_results[cid] = 'Suspended (ongoing)'
                print(f"    Client {cid:2d} — already suspended, skipping.")
                continue

            rewards_epoch = self.reward_buffer.get(cid, [])
            G = (self.compute_discounted_return(rewards_epoch)
                 if rewards_epoch else 0.0)

            continues = self.epoch_action(cid, G)

            if continues:
                epoch_results[cid] = 'Continue'
            else:
                epoch_results[cid] = 'Suspended'
                self.suspend_client(cid)
                suspended_this.append(cid)

        self.suspension_history[self.epoch_count] = suspended_this

        # Reset reward buffers for active clients
        for cid in self.reward_buffer:
            if not self.is_suspended(cid):
                self.reward_buffer[cid] = []

        # Count down existing bans
        self.decrement_bans()

        print(f"\n  Epoch {self.epoch_count} suspended: {suspended_this}")
        return epoch_results


# MQTT MONITOR
class MQTTSecMonitor:
    """
    Subscribes to all MQTT traffic on the broker.
    Collects messages per client, batches them into episodes,
    and drives the RLenv.

    Topic convention used by publishers:
        mqttsec/c{client_id}/{msg_type}
        e.g.  mqttsec/c3/qos1
              mqttsec/c12/connect

    Payload JSON (from publishers):
        {"cid": 3, "is_attack": 0, "data": "AAAA..."}
    """

    def __init__(self, rl_env):
        self.rl_env    = rl_env
        self.last_seen = {}    # client_id → last message timestamp (s)
        self.pending   = {}    # client_id → latest client dict
        self.lock      = threading.Lock()
        self.running   = True

        # CSV log
        self.log_fh  = open(LOG_FILE, 'w', newline='')
        self.log_csv = csv.writer(self.log_fh)
        self.log_csv.writerow([
            'wall_time', 'client_id', 'msg_type',
            'payload_len', 'timedelta_ms', 'true_label',
            'ml_state', 'action', 'reward',
            'episode', 'epoch'
        ])

        try:
            self.mqtt_client = mqtt.Client(
                client_id="mqttsec_monitor",
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2
            )
        except (AttributeError, TypeError):
            self.mqtt_client = mqtt.Client(client_id="mqttsec_monitor")

        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message

    # Mosquitto callbacks

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = getattr(reason_code, 'value', reason_code)
        if int(rc) == 0:
            print(f"[Monitor] Connected to Mosquitto at {BROKER_IP}:{BROKER_PORT}")
            client.subscribe("mqttsec/#")
            print("[Monitor] Subscribed to mqttsec/#")
        else:
            print(f"[Monitor] Connection failed, rc={reason_code}")

    def _on_message(self, client, userdata, msg):
        now   = time.time()
        topic = msg.topic          # e.g. "mqttsec/c3/qos1"
        parts = topic.split('/')

        # Validate topic structure
        if len(parts) < 3 or not parts[1].startswith('c'):
            return

        try:
            cid      = int(parts[1][1:])   # strip leading 'c'
            msg_type = parts[2]            # qos0 / qos1 / connect
        except ValueError:
            return

        if msg_type not in ('qos0', 'qos1', 'connect'):
            return

        payload_len = len(msg.payload)

        # Parse ground truth label from publisher payload
        try:
            payload_str  = msg.payload.decode('utf-8', errors='ignore')
            payload_json = json.loads(payload_str)
            true_label   = int(payload_json.get('is_attack', 0))
        except Exception:
            true_label = 0

        # Compute time delta in milliseconds
        with self.lock:
            if cid in self.last_seen:
                td_ms = (now - self.last_seen[cid]) * 1000.0
            else:
                td_ms = THETA2_MAX   # first message — assume safe
            self.last_seen[cid] = now

            # Keep the most recent message from each client for this episode
            self.pending[cid] = {
                'id':           cid,
                'msg_type':     msg_type,
                'timedelta_ms': round(td_ms, 2),
                'payload_len':  payload_len,
                'true_label':   true_label
            }

    # Episode loop - runs in a background thread

    def _episode_loop(self):
        """
        Every EPISODE_WINDOW_SEC seconds, take whatever messages have
        accumulated and run one RL episode.
        """
        action_map = {1: 'accept', 2: 'warn', 0: 'decline'}

        while self.running:
            time.sleep(EPISODE_WINDOW_SEC)

            with self.lock:
                if not self.pending:
                    continue
                clients      = list(self.pending.values())
                self.pending = {}

            if not clients:
                continue

            print(f"\n[Monitor] Episode window closed — "
                  f"{len(clients)} clients collected")

            rewards, epoch_results = self.rl_env.run_episode(clients)

            # Log every client's outcome this episode
            wall = time.strftime("%H:%M:%S")
            for client, reward in zip(clients, rewards):
                cid  = client['id']
                plen = client['payload_len']
                td   = client['timedelta_ms']
                lbl  = client['true_label']
                ml   = self.rl_env.model.predict(plen, td)
                act  = action_map.get(reward, '?')
                self.log_csv.writerow([
                    wall, cid, client['msg_type'], plen, td, lbl,
                    ml, act, reward,
                    self.rl_env.episode_count,
                    self.rl_env.epoch_count
                ])
            self.log_fh.flush()

            # Print epoch summary if epoch just completed
            if epoch_results:
                print(f"\n[Monitor] Epoch {self.rl_env.epoch_count} complete:")
                for cid, outcome in epoch_results.items():
                    print(f"          Client {cid:2d} → {outcome}")

                # Save intermediate plots every epoch
                self._save_plots()

            # Stop when target epochs reached
            if self.rl_env.epoch_count >= N_EPOCHS:
                print(f"\n[Monitor] {N_EPOCHS} epochs complete. Stopping.")
                self.running = False
                break

    # Plotting

    def _save_plots(self):
        epochs = list(range(1, len(self.rl_env.epoch_epsilon_history) + 1))
        if not epochs:
            return

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))

        # Plot 1 — accumulated returns per client
        axes[0].bar(range(NUM_CLIENTS), self.rl_env.return1, color='steelblue')
        axes[0].set_xlabel('Client ID',     fontweight='bold')
        axes[0].set_ylabel('Return',        fontweight='bold')
        axes[0].set_title('Accumulated Returns')

        # Plot 2 — epsilon over epochs
        axes[1].plot(epochs, self.rl_env.epoch_epsilon_history,
                     'b--', linewidth=2, label='ε')
        axes[1].plot(epochs, self.rl_env.epoch_error_history,
                     'r-',  linewidth=2, label='ML error')
        axes[1].set_xlabel('Epoch',  fontweight='bold')
        axes[1].set_ylabel('Value',  fontweight='bold')
        axes[1].set_title('ε and ML Error over Epochs')
        axes[1].legend()

        plt.tight_layout()
        plt.savefig('mqttsec_progress.png', dpi=150)
        plt.close(fig)

    # Start / stop

    def start(self):
        try:
            self.mqtt_client.connect(BROKER_IP, BROKER_PORT, keepalive=60)
        except OSError as e:
            print(f"[Monitor] Could not connect to {BROKER_IP}:{BROKER_PORT} ({e})")
            self.running = False
            self.log_fh.close()
            return

        ep_thread = threading.Thread(
            target=self._episode_loop, daemon=True, name="EpisodeLoop"
        )
        ep_thread.start()
        print("[Monitor] Episode loop started.")

        try:
            self.mqtt_client.loop_forever()
        except KeyboardInterrupt:
            print("\n[Monitor] Interrupted by user.")
        finally:
            self.running = False
            self.mqtt_client.disconnect()
            self._save_final_report()
            self.log_fh.close()
            print("[Monitor] Stopped.")

    def _save_final_report(self):
        with open(RESULTS_FILE, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("MQTTSec Final Report\n")
            f.write("=" * 60 + "\n\n")

            f.write("Accumulated Returns per Client\n")
            f.write("-" * 40 + "\n")
            for i, ret in enumerate(self.rl_env.return1):
                status = "(SUSPENDED)" if self.rl_env.is_suspended(i) else ""
                f.write(f"  Client {i:2d}  return={ret:6.1f}  {status}\n")

            f.write(f"\nTotal epochs completed : {self.rl_env.epoch_count}\n")
            f.write(f"Final ε                : {self.rl_env.epsilon:.4f}\n")
            f.write(f"Final ML error         : "
                    f"{self.rl_env.last_classification_error:.4f}\n")

            f.write("\nSuspensions per Epoch\n")
            f.write("-" * 40 + "\n")
            for epoch, suspended in self.rl_env.suspension_history.items():
                f.write(f"  Epoch {epoch:3d}: {suspended}\n")

        print(f"[Monitor] Final report saved → {RESULTS_FILE}")
        self._save_plots()
        print("[Monitor] Plots saved → mqttsec_progress.png")


# MAIN
if __name__ == '__main__':
    random.seed(42)
    np.random.seed(42)

    print("=" * 60)
    print("  MQTTSec Broker Monitor")
    print(f"  Target: {N_EPOCHS} epochs × {N_EPISODES} episodes")
    print(f"  RF retrain every {RETRAIN_INT} epochs")
    print(f"  Thresholds: θ1=[{THETA1_MIN},{THETA1_MAX}]B  "
          f"θ2=[{THETA2_MIN},{THETA2_MAX}]ms")
    print(f"  τE={TAU_EPOCH}  εr={EPSILON_R}  γ={GAMMA}")
    print("=" * 60)

    model   = RFModel("rf_model.pkl")
    rl_env  = RLenv(model, num_clients=NUM_CLIENTS)
    monitor = MQTTSecMonitor(rl_env)
    monitor.start()
