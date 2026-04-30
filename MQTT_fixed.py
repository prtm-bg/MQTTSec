import random
import math
import numpy as np
import matplotlib.pyplot as plt




class RLenv:
    def __init__(self, model, num_clients=15,
                 gamma=0.9,          
                 tau_epoch=5.0,      
                 epsilon_r=0.05,     
                 ban_duration=2):    
        self.model        = model
        self.num_clients  = num_clients
        self.gamma        = gamma
        self.tau_epoch    = tau_epoch
        self.epsilon_r    = epsilon_r
        self.epsilon      = epsilon_r   
        self.ban_duration = ban_duration

        # Per-client reward history across all episodes in the current epoch
        
        self.reward_buffer = {i: [] for i in range(num_clients)}

        # Accumulated return across the whole run
        self.return1 = [0 for _ in range(num_clients)]

        # Suspension registry  {client_id: epochs_remaining_in_ban}
        self.suspended = {}

        # Tracking
        self.episode_count  = 0      # episodes within current epoch
        self.epoch_count    = 0
        self.episodes_per_epoch = 10

        # Last episode's ML classification error (used to update ε)
        self.last_classification_error = 0.0

    # ------------------------------------------------------------------ #
    #  STATE                                                               #
    # ------------------------------------------------------------------ #

    def get_state(self, timedelta, msg_type, window_size):
        return self.machine_learning_input(timedelta, msg_type, window_size)

    def machine_learning_input(self, timedelta, msg_type, window_size):
        msg_type_map = {'qos0': 0, 'qos1': 1, 'connect': 2}
        msg_id = msg_type_map.get(msg_type, -1)
        features = np.array([[timedelta, msg_id, window_size if window_size is not None else 0]])
        prediction = self.model.predict(features)
        return int(prediction[0])   # state ∈ {0, 1, 2}

    # ------------------------------------------------------------------ #
    #  EPISODE-LEVEL ACTION POLICY  (A1 / A2)                             #
    # ------------------------------------------------------------------ #

    def check_msg_type(self, msg_field, timedelta, threshold1, window_size=None):
        
        threshold2 = 8

        if msg_field == 'qos0':
            # A2 — only timedelta matters
            if timedelta >= threshold1:
                return self.send_message_accept()
            else:
                return self.send_message_decline()

        if msg_field in ['qos1', 'connect']:
            if window_size is None:
                raise ValueError(f"Missing window_size for msg_type '{msg_field}'")
            combined = timedelta + window_size
            if combined < threshold1:
                return self.send_message_accept()
            elif threshold1 <= combined <= threshold2:
                return self.send_message_warn()
            else:
                return self.send_message_decline()

        print(f"Warning: unknown msg_field '{msg_field}', defaulting to decline.")
        return self.send_message_decline()

    #  REWARD SIGNALS                                                      
   

    def send_message_accept(self):
        return 1

    def send_message_decline(self):
        return 0

    def send_message_warn(self):
        return 2

    def reward_return(self, actions):
        rewards = []
        for action in actions:
            if action == 1:
                print("  Action: Accept  -> reward +1")
                rewards.append(1)
            elif action == 2:
                print("  Action: Warn    -> reward +2")
                rewards.append(2)
            else:
                print("  Action: Decline -> reward  0")
                rewards.append(0)
        return rewards

    
    #  EPOCH-LEVEL: DISCOUNTED RETURN                                      
    

    def compute_discounted_return(self, rewards):
        
        G = 0.0
        for k, r in enumerate(rewards):
            G += (self.gamma ** k) * r
        return G

    #  EPOCH-LEVEL: ε UPDATE                                               
    

    def update_epsilon(self, classification_error):
        
        self.epsilon = self.epsilon_r + classification_error / 2.0
        self.epsilon = min(self.epsilon, 1.0)   # cap at 1

    
    #  EPOCH-LEVEL

    def epoch_action(self, client_id, G):
        
        if random.random() < self.epsilon:
            # Exploration — random action
            action = random.choice(['Continue', 'Suspend'])
            print(f"  [ε-greedy EXPLORE] Client {client_id} → {action}  (G={G:.3f})")
        else:
            # Exploitation — use return vs threshold
            action = 'Continue' if G > self.tau_epoch else 'Suspend'
            print(f"  [ε-greedy EXPLOIT] Client {client_id} → {action}  (G={G:.3f}, τ={self.tau_epoch})")

        return action == 'Continue'

    
    #  SUSPENSION MANAGEMENT                


    def suspend_client(self, client_id):
        
        self.reward_buffer[client_id] = []
        self.suspended[client_id]     = self.ban_duration
        print(f"  *** Client {client_id} SUSPENDED for {self.ban_duration} epoch(s) ***")

    def decrement_bans(self):
       
        to_reinstate = []
        for cid, remaining in self.suspended.items():
            self.suspended[cid] = remaining - 1
            if self.suspended[cid] <= 0:
                to_reinstate.append(cid)
        for cid in to_reinstate:
            del self.suspended[cid]
            print(f"  Client {cid} reinstated after ban.")

    def is_suspended(self, client_id):
        return client_id in self.suspended

    # ------------------------------------------------------------------ #
    #  EPISODE LOOP                                                        #
    # ------------------------------------------------------------------ #

    def run_episode(self, clients):
        
        print(f"\n  -- Episode {self.episode_count + 1} within Epoch {self.epoch_count + 1} --")

        actions      = []
        active_ids   = []

        for client in clients:
            cid      = client['id']
            msg_type = client['msg_type']
            td       = client['timedelta']
            ws       = client.get('window_size', None)

            # Skip suspended clients
            if self.is_suspended(cid):
                print(f"  Client {cid} is SUSPENDED — skipping.")
                continue

            if msg_type in ['qos1', 'connect'] and ws is None:
                print(f"  Skipping client {cid} — missing window_size")
                continue

            state  = self.get_state(td, msg_type, ws)
            print(f"  Client {cid} | msg={msg_type} | td={td} | ws={ws} | state={state}")

            action = self.check_msg_type(msg_type, td, threshold1=5, window_size=ws)
            actions.append(action)
            active_ids.append(cid)

        rewards = self.reward_return(actions)

        # Store rewards in per-client buffer
        for cid, r in zip(active_ids, rewards):
            self.reward_buffer[cid].append(r)
            self.return1[cid] += r

        # ---------- simulated ML error for this episode ----------
        # In a real system this comes from your ML model's test error.
        # Here we simulate it as a small random value.
        self.last_classification_error = random.uniform(0.0, 0.3)

        self.episode_count += 1

        # ---------- check epoch boundary ----------
        epoch_results = None
        if self.episode_count >= self.episodes_per_epoch:
            epoch_results = self._run_epoch_evaluation(clients)
            self.episode_count = 0   # reset for next epoch

        return rewards, epoch_results

    # ------------------------------------------------------------------ #
    #  EPOCH EVALUATION                                                    #
    # ------------------------------------------------------------------ #

    def _run_epoch_evaluation(self, clients):
        
        self.epoch_count += 1
        print(f"\n{'#'*60}")
        print(f"  EPOCH {self.epoch_count} EVALUATION")
        print(f"  Classification error (last episode): "
              f"{self.last_classification_error:.3f}")
        print(f"{'#'*60}")

        # 1. Update ε
        self.update_epsilon(self.last_classification_error)
        print(f"  Updated ε = {self.epsilon:.4f}")

        epoch_results = {}

        for client in clients:
            cid = client['id']

            if self.is_suspended(cid):
                # Already suspended — skip evaluation
                epoch_results[cid] = 'Suspended (ongoing)'
                continue

            rewards_this_epoch = self.reward_buffer.get(cid, [])

            if not rewards_this_epoch:
                # Client produced no traffic (or was skipped all episode) —
                # treat as zero return → likely Suspend
                G = 0.0
            else:
                G = self.compute_discounted_return(rewards_this_epoch)

            continues = self.epoch_action(cid, G)

            if continues:
                epoch_results[cid] = 'Continue'
            else:
                epoch_results[cid] = 'Suspended'
                self.suspend_client(cid)

        # 4. Reset reward buffers for the next epoch
        for cid in self.reward_buffer:
            if not self.is_suspended(cid):
                self.reward_buffer[cid] = []

        # 5. Decrement existing bans (they started this epoch; next epoch they
        #    get one epoch closer to reinstatement)
        self.decrement_bans()

        return epoch_results


# ====================================================================== #
#  TEST ENVIRONMENT                                                        #
# ====================================================================== #

class testEnv:
    def __init__(self, seed=None):
        if seed is not None:
            random.seed(seed)
        self.clients = []
        self.create_clients()

    def create_clients(self):
        msg_types = ['qos0'] * 5 + ['qos1'] * 5 + ['connect'] * 5
        random.shuffle(msg_types)

        for i, msg_type in enumerate(msg_types):
            client = {
                'id':        i,
                'msg_type':  msg_type,
                'timedelta': round(random.uniform(0, 10), 2),
            }
            if msg_type in ['qos1', 'connect']:
                client['window_size'] = round(random.uniform(1, 5), 2)

            print(client)
            self.clients.append(client)


# ====================================================================== #
#  DUMMY MODEL                                                             #
# ====================================================================== #

class DummyModel:
    """Placeholder — always predicts state 0 (benign)."""
    def predict(self, X):
        return [0] * len(X)


# ====================================================================== #
#  PLOTTING HELPER                                                         #
# ====================================================================== #

def plot_accumulated_returns(return1):
    fig, ax = plt.subplots(figsize=(10, 4))
    client_ids = list(range(len(return1)))
    ax.bar(client_ids, return1, color='steelblue', edgecolor='white')
    ax.set_xlabel('Client ID')
    ax.set_ylabel('Accumulated Return')
    ax.set_title('Accumulated Returns per Client (all epochs)')
    ax.set_xticks(client_ids)
    plt.tight_layout()
    plt.savefig('accumulated_returns.png', dpi=150)
    plt.show()
    print("Plot saved to accumulated_returns.png")


def plot_qos1_message_length():
    """Stub kept for backward compatibility with the original notebook."""
    lengths = np.random.exponential(scale=50, size=500)
    plt.figure(figsize=(8, 4))
    plt.hist(lengths, bins=30, color='coral', edgecolor='white')
    plt.title('QoS-1 Message Length Distribution (simulated)')
    plt.xlabel('Payload Length (bytes)')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('qos1_message_length.png', dpi=150)
    plt.show()


# ====================================================================== #
#  MAIN                                                                    #
# ====================================================================== #

if __name__ == '__main__':
    random.seed(0)
    np.random.seed(0)

    NUM_EPOCHS            = 3   # total epochs to run
    EPISODES_PER_EPOCH    = 10  # fixed by the paper

    model    = DummyModel()
    test_env = testEnv(seed=42)
    rl_env   = RLenv(
        model,
        num_clients       = len(test_env.clients),
        gamma             = 0.9,
        tau_epoch         = 5.0,
        epsilon_r         = 0.05,
        ban_duration      = 1,    # suspended clients miss 1 epoch
    )

    total_episodes = NUM_EPOCHS * EPISODES_PER_EPOCH
    epoch_summary  = {}   # {epoch_number: epoch_results_dict}

    for ep in range(total_episodes):
        global_ep = ep + 1
        print(f"\n{'='*60}")
        print(f"Episode {global_ep:3d} / {total_episodes}  "
              f"(Epoch {rl_env.epoch_count + 1}, "
              f"episode-within-epoch {rl_env.episode_count + 1})")
        print('='*60)

        rewards, epoch_results = rl_env.run_episode(test_env.clients)

        if epoch_results is not None:
            epoch_summary[rl_env.epoch_count] = epoch_results
            print(f"\n  Epoch {rl_env.epoch_count} summary:")
            for cid, outcome in epoch_results.items():
                print(f"    Client {cid:2d}: {outcome}")

    # ------------------------------------------------------------------
    print("\n\n" + "="*60)
    print("FINAL ACCUMULATED RETURNS")
    print("="*60)
    for i, ret in enumerate(rl_env.return1):
        status = "(SUSPENDED)" if rl_env.is_suspended(i) else ""
        print(f"  Client {i:2d}  accumulated return: {ret:5.1f}  {status}")

    plot_accumulated_returns(rl_env.return1)
    plot_qos1_message_length()
