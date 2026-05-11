#!/usr/bin/env python3
# mqtt_tui.py
# A gorgeous btop/htop-style terminal UI to monitor the MQTTSec experiment.
# Spawns the broker and publishers, tracking their stdout in real-time.

import curses
import subprocess
import threading
import queue
import time
import os
import sys

BROKER_CMD = ["python3", "-u", "mqttsec_broker.py"]
DYN_PUB_CMD = ["python3", "-u", "dynamic_publisher.py", "--broker", "127.0.0.1"]

class MQTTSecTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.q = queue.Queue()
        
        self.epoch = 0
        self.max_epochs = 60
        self.episode = 0
        self.max_episodes = 10
        self.last_err = 0.0
        self.epsilon = 0.1
        
        self.disp_epoch = 0
        self.disp_episode = 0
        self.last_progress_update = time.time()
        
        self.processes = []
        self.logs = []
        self.max_log_lines = 15
        self.clients = {i: {"status": "OK", "role": "Benign"} for i in range(15)} # dynamic
        self.running = True
        
        # Init curses
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)   # OK / Progress
        curses.init_pair(2, curses.COLOR_RED, -1)     # Attack/Suspended
        curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warnings
        curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info headers

        self.start_processes()

    def stop_processes(self):
        for p in self.processes:
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except:
                pass
                
    def start_processes(self):
        # Auto-detect folder paths based on local macOS or Ubuntu SSH layout
        if os.path.exists("mqttsec_broker.py"):
            broker_dir = "."
            pub_dir = "."
        else:
            home = os.path.expanduser("~")
            broker_dir = os.path.join(home, "mqtt-broker")
            pub_dir = os.path.join(home, "mqtt-publishers")
            
        try:
            pb = subprocess.Popen(BROKER_CMD, cwd=broker_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.processes.append(pb)
            
            time.sleep(2) # Give broker an initial start lead
            
            pdyn = subprocess.Popen(DYN_PUB_CMD, cwd=pub_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.processes.append(pdyn)
            
        except Exception as e:
            self.q.put(f"[SYSTEM] Error starting processes: {e}")
            
        for p in self.processes:
            threading.Thread(target=self.read_output, args=(p,), daemon=True).start()

    def read_output(self, p):
        try:
            for line in iter(p.stdout.readline, ''):
                if line:
                    self.q.put(line.strip())
        except: pass

    def process_logs(self):
        while not self.q.empty():
            line = self.q.get()
            self.add_log(line)
            
            # Simple keyword hooks into the stdout text to extract live metrics!
            if "Episode" in line and "Epoch" in line:
                try:
                    parts = line.split('|')
                    ep_part = parts[0].strip()
                    ek_part = parts[1].strip()
                    # Example parsed formats -> Episode 1/10 | Epoch 5/300
                    self.episode = int(ep_part.split(' ')[1].split('/')[0])
                    self.epoch = int(ek_part.split(' ')[1].split('/')[0])
                except: pass
            elif "SUSPENDED" in line and "Client" in line:
                try:
                    cid = int([w for w in line.split() if w.isdigit()][0])
                    if cid in self.clients: self.clients[cid]["status"] = "BANNED"
                except: pass
            elif "reinstated" in line and "Client" in line:
                try:
                    cid = int([w for w in line.split() if w.isdigit()][0])
                    if cid in self.clients: self.clients[cid]["status"] = "OK"
                except: pass
            elif "[Dynamic]" in line and "is now" in line:
                # Log line from dynamic publisher: "[Dynamic] Client {cid} is now {role}"
                try:
                    parts = line.split("Client")[1].split("is now")
                    cid = int(parts[0].strip())
                    role = parts[1].strip()
                    if cid in self.clients: self.clients[cid]["role"] = min(role, key=len) if len(role) > 6 else role[:6]
                except: pass
            elif "classification error" in line:
                try: self.last_err = float(line.split(':')[-1].strip())
                except: pass
            elif "Updated ε =" in line:
                try: self.epsilon = float(line.split('=')[1].strip().split()[0])
                except: pass
            elif "Target: " in line and " epochs " in line:
                try: self.max_epochs = int(line.split('Target:')[1].strip().split(' ')[0])
                except: pass
                
    def add_log(self, text):
        if text.replace("-", "").replace("#", "").strip() == "" or text.replace("=", "").strip() == "": 
            return
        self.logs.append(text)
        if len(self.logs) > self.max_log_lines:
            self.logs.pop(0)

    def draw_progress(self, y, x, label, val, mval, width=40):
        self.stdscr.addstr(y, x, f"{label:10s} [")
        pct = min(1.0, val / mval if mval > 0 else 0)
        filled = int(width * pct)
        
        self.stdscr.attron(curses.color_pair(1))
        self.stdscr.addstr("█" * filled)
        self.stdscr.attroff(curses.color_pair(1))
        
        self.stdscr.addstr(" " * (width - filled) + f"] {val}/{mval}")

    def draw(self):
        self.disp_epoch = self.epoch
        self.disp_episode = self.episode
        
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        if h < 20 or w < 75:
            self.stdscr.addstr(0, 0, "Terminal window too small! Please resize.")
            self.stdscr.refresh()
            return
            
        self.max_log_lines = max(5, h - 18)
        
        # Header
        header = " 📊 MQTTSec System Monitor "
        self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, header.center(w, "="))
        self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        # Progress (updated every 2 seconds)
        self.draw_progress(2, 2, "Epochs", self.disp_epoch, self.max_epochs, width=40)
        self.draw_progress(3, 2, "Episodes", self.disp_episode, self.max_episodes, width=40)
        self.stdscr.addstr(5, 2, f"Latest RF Error : {self.last_err:.4f}")
        self.stdscr.addstr(6, 2, f"RL Epsilon (ε)  : {self.epsilon:.4f}")
        
        # Clients Grid
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(8, 0, " Client Status Matrix ".center(w, "-"))
        self.stdscr.attroff(curses.color_pair(4))
        
        for i in range(15):
            row = 10 + (i % 5)
            col = 5 + (30 * (i // 5)) # 3 columns
            
            c_type = self.clients[i]["role"]
            status = self.clients[i]["status"]
            
            color = curses.color_pair(1) if status == "OK" else curses.color_pair(2)
            c_type_color = curses.color_pair(2) if "attack" in c_type.lower() else curses.color_pair(1)
            if "inacti" in c_type.lower():
                c_type_color = curses.color_pair(3)
            
            self.stdscr.addstr(row, col, f"[{i:2d}] ")
            self.stdscr.attron(c_type_color)
            self.stdscr.addstr(f"{c_type:6s}")
            self.stdscr.attroff(c_type_color)
            
            self.stdscr.addstr(" : ")
            self.stdscr.attron(color)
            self.stdscr.addstr(f"{status:6s}")
            self.stdscr.attroff(color)
            
        # Logs
        log_y = 16
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(log_y, 0, " Live Console Streams ".center(w, "-"))
        self.stdscr.attroff(curses.color_pair(4))
        
        for i, log in enumerate(self.logs[-self.max_log_lines:]):
            safe_log = log[:w-4]
            self.stdscr.addstr(log_y + 1 + i, 2, f"{safe_log}")

        # Footer
        footer = " Press [q] to stop experiment and exit cleanly "
        self.stdscr.attron(curses.color_pair(3))
        try:
            self.stdscr.addstr(h-1, 0, footer.center(w - 1, "="))
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(3))
        
        self.stdscr.refresh()

    def run(self):
        self.stdscr.nodelay(1)
        self.stdscr.timeout(100) # Draw loop interval (ms)
        
        try:
            while self.running:
                c = self.stdscr.getch()
                if c == ord('q'):
                    self.running = False
                
                self.process_logs()
                self.draw()
        finally:
            self.stdscr.clear()
            self.stdscr.addstr(max(0, self.stdscr.getmaxyx()[0]//2), max(0, self.stdscr.getmaxyx()[1]//2 - 15), "Shutting down processes...")
            self.stdscr.refresh()
            self.stop_processes()

def run_tui(stdscr):
    app = MQTTSecTUI(stdscr)
    app.run()

if __name__ == "__main__":
    try:
        curses.wrapper(run_tui)
    except KeyboardInterrupt:
        pass
    print("\nDone. MQTTSec monitor successfully terminated.")
