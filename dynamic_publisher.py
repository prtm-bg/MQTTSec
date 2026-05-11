# dynamic_publisher.py
# Simulates clients up to NUM_CLIENTS=15 (to match mqttsec_broker.py constraints).
# Dynamically swaps roles: benign, attacker, or inactive (join/leave simulation).
#
# Usage:
#   python3 dynamic_publisher.py --broker 192.168.1.100

import paho.mqtt.client as mqtt
import time
import random
import json
import argparse
import socket
import threading

# Configuration constraints
NUM_CLIENTS = 15 # Required by mqttsec_broker.py

# Safe parameter ranges (stay inside paper's θ thresholds)
BENIGN_QOS0_PAYLOAD  = (4, 8)       
BENIGN_QOS0_SLEEP    = (35, 60)     

BENIGN_QOS1_PAYLOAD  = (4, 8)       
BENIGN_QOS1_SLEEP    = (60, 80)     

BENIGN_CONNECT_PAYLOAD = (4, 8)
BENIGN_CONNECT_SLEEP   = (60, 80)

# Attack parameters
ATTACK_CONNECT_PAYLOAD = (660, 900)   
ATTACK_CONNECT_SLEEP   = (1, 3)       

ATTACK_QOS0_PAYLOAD    = (4, 8)       
ATTACK_QOS0_SLEEP      = (1, 4)       

ATTACK_QOS1_PAYLOAD   = (660, 1000)  
ATTACK_QOS1_SLEEP     = (2, 4)       

def create_mqtt_client(client_id):
    try:
        return mqtt.Client(
            client_id=client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2
        )
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id)

def make_payload(cid, target_bytes, is_attack=0):
    base    = json.dumps({"cid": cid, "is_attack": is_attack, "data": ""})
    padding = max(0, target_bytes - len(base.encode()))
    return json.dumps({
        "cid":       cid,
        "is_attack": is_attack,
        "data":      "X" * padding if is_attack else "B" * padding
    }).encode()

class DynamicClient(threading.Thread):
    def __init__(self, cid, broker_ip, broker_port):
        super().__init__(daemon=True)
        self.cid = cid
        self.broker_ip = broker_ip
        self.broker_port = broker_port
        self.client = create_mqtt_client(f"dyn_pub_{self.cid}")
        self.running = True
        
        # State: 'inactive', 'benign', 'attacker'
        self.role = 'inactive'
        self.sub_type = 'qos0' # 'qos0', 'qos1', 'connect'
        
    def run(self):
        try:
            self.client.connect(self.broker_ip, self.broker_port, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            print(f"[Client {self.cid}] Connect failed: {e}")
            return
            
        while self.running:
            role = self.role
            sub_type = self.sub_type
            
            if role == 'inactive':
                time.sleep(1)
                continue
                
            if role == 'benign':
                if sub_type == 'qos0':
                    plen  = random.randint(*BENIGN_QOS0_PAYLOAD)
                    sleep = random.randint(*BENIGN_QOS0_SLEEP) / 1000.0
                elif sub_type == 'qos1':
                    plen  = random.randint(*BENIGN_QOS1_PAYLOAD)
                    sleep = random.randint(*BENIGN_QOS1_SLEEP) / 1000.0
                else: # connect
                    plen  = random.randint(*BENIGN_CONNECT_PAYLOAD)
                    sleep = random.randint(*BENIGN_CONNECT_SLEEP) / 1000.0
                is_attack = 0
            
            elif role == 'attacker':
                if sub_type == 'qos0': # fast flood
                    plen  = random.randint(*ATTACK_QOS0_PAYLOAD)
                    sleep = random.randint(*ATTACK_QOS0_SLEEP) / 1000.0
                elif sub_type == 'qos1': # heavy flood
                    plen  = random.randint(*ATTACK_QOS1_PAYLOAD)
                    sleep = random.randint(*ATTACK_QOS1_SLEEP) / 1000.0
                else: # connect flood
                    plen  = random.randint(*ATTACK_CONNECT_PAYLOAD)
                    sleep = random.randint(*ATTACK_CONNECT_SLEEP) / 1000.0
                is_attack = 1

            topic = f"mqttsec/c{self.cid}/{sub_type}"
            payload = make_payload(self.cid, plen, is_attack)
            qos = 0 if sub_type == 'qos0' else 1

            try:
                self.client.publish(topic, payload, qos=qos)
            except Exception:
                pass
                
            time.sleep(sleep)
            
        self.client.loop_stop()
        self.client.disconnect()


def run_dynamic_publisher(broker_ip, broker_port):
    print(f"Starting dynamic publisher to {broker_ip}:{broker_port}")
    print(f"Managing up to {NUM_CLIENTS} clients dynamically (ID 0-{NUM_CLIENTS-1})")
    
    clients = []
    for cid in range(NUM_CLIENTS):
        c = DynamicClient(cid, broker_ip, broker_port)
        c.start()
        clients.append(c)
        
    # Initial state simulation (just to mirror the old setup roughly initially)
    for i in range(10):
        clients[i].role = 'benign'
        clients[i].sub_type = random.choice(['qos0', 'qos1', 'connect'])
    for i in range(10, min(15, NUM_CLIENTS)):
        clients[i].role = 'attacker'
        clients[i].sub_type = random.choice(['qos0', 'qos1', 'connect'])
        
    print("Clients started. Dynamic role-swapping begins now.")
    
    try:
        while True:
            # Change random client state every few seconds
            time.sleep(10)
            target = random.choice(clients)
            
            # Weighted choice to mostly have active clients
            new_role = random.choices(['inactive', 'benign', 'attacker'], weights=[0.2, 0.5, 0.3], k=1)[0]
            new_sub = random.choice(['qos0', 'qos1', 'connect'])
            
            old_role = target.role
            target.role = new_role
            target.sub_type = new_sub
            
            if old_role != new_role:
                print(f"[Manager] SWAP: Client C{target.cid} {old_role} -> {new_role} ({new_sub})")
            
    except KeyboardInterrupt:
        print("\nStopping all clients...")
        for c in clients:
            c.running = False
            c.role = 'inactive'
        for c in clients:
            c.join()
        print("Stopped.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dynamic MQTT Publisher")
    parser.add_argument('--broker', default='192.168.1.100',
                        help='Broker IP. Default: 192.168.1.100')
    parser.add_argument('--port',   default=1883, type=int,
                        help='Broker port. Default: 1883')
    args = parser.parse_args()

    run_dynamic_publisher(args.broker, args.port)