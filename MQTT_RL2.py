# -*- coding: utf-8 -*-
"""MQTT_fixed.py — Completed and corrected version of MQTT.ipynb"""

import random
import numpy as np
import matplotlib.pyplot as plt


class RLenv:
    def __init__(self, model, num_clients=15):
        self.model = model
        self.return1 = [0 for _ in range(num_clients)]

    # ------------------------------------------------------------------ #
    #  STATE                                                               #
    # ------------------------------------------------------------------ #

    def get_state(self, timedelta, msg_type, window_size):
        
        state = self.machine_learning_input(timedelta, msg_type, window_size)
        return state

    def machine_learning_input(self, timedelta, msg_type, window_size):
        
        msg_type_map = {'qos0': 0, 'qos1': 1, 'connect': 2}
        msg_id = msg_type_map.get(msg_type, -1)

        features = np.array([[timedelta, msg_id, window_size if window_size is not None else 0]])
        prediction = self.model.predict(features)
        return int(prediction[0])   # state ∈ {0, 1, 2}

    # ------------------------------------------------------------------ #
    #  ACTION POLICY                                                       #
    # ------------------------------------------------------------------ #

    def check_msg_type(self, msg_field, timedelta, threshold1, window_size=None):
        
        threshold2 = 8

        if msg_field == 'qos0':
            # qos0 only uses timedelta — no window_size needed
            if timedelta < threshold1:
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

        # Unknown message type — treat as decline
        print(f"Warning: unknown msg_field '{msg_field}', defaulting to decline.")
        return self.send_message_decline()

    # ------------------------------------------------------------------ #
    #  REWARD SIGNALS                                                      #
    # ------------------------------------------------------------------ #

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
                print("Action: Accept")
                rewards.append(1)
            elif action == 2:
                print("Action: Warn")
                rewards.append(2)
            else:
                print("Action: Decline")
                rewards.append(0)
        return rewards

    # ------------------------------------------------------------------ #
    #  EPISODE LOOP                                                        #
    # ------------------------------------------------------------------ #

    def run_episode(self, clients):
        
        actions = []

        for client in clients:
            msg_type  = client['msg_type']
            td        = client['timedelta']
            ws        = client.get('window_size', None)

            if msg_type in ['qos1', 'connect'] and ws is None:
                print(f"Skipping client {client['id']} — missing window_size")
                continue

            # Derive ML state (unused by the rule-based policy but available
            # for a learned policy to consume)
            state = self.get_state(td, msg_type, ws)
            print(f"Client {client['id']} | msg={msg_type} | td={td} | ws={ws} | state={state}")

            action = self.check_msg_type(msg_type, td, threshold1=5, window_size=ws)
            actions.append(action)

        rewards = self.reward_return(actions)

        for i, r in enumerate(rewards):
            self.return1[i] += r

        return rewards


# ====================================================================== #
#  TEST ENVIRONMENT                                                        #
# ====================================================================== #

class testEnv:
    def __init__(self):
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

            # window_size is only relevant for qos1 and connect
            if msg_type in ['qos1', 'connect']:
                client['window_size'] = 2   # fixed for reproducibility

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
#  MAIN                                                                    #
# ====================================================================== #

if __name__ == '__main__':
    random.seed(0)
    np.random.seed(0)

    model    = DummyModel()
    test_env = testEnv()
    rl_env   = RLenv(model, num_clients=len(test_env.clients))

    for episode in range(10):
        print(f"\n{'='*40}")
        print(f"Episode: {episode}")
        rl_env.run_episode(test_env.clients)

    print("\n--- Accumulated returns ---")
    for i, ret in enumerate(rl_env.return1):
        print(f"Client {i:2d} accumulated return: {ret}")



if __name__ == '__main__':
    plot_qos1_message_length()
