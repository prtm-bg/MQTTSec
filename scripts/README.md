# MQTTSec Raspberry Pi Test Scripts

This folder contains a complete test harness for your 3-device setup:

- RPi5: broker + MQTTSec runtime
- RPi4-A: normal publisher
- RPi4-B: attacker publisher

## Files

- `mqttsec_runtime.py`: broker-side filtering runtime (rule/model/hybrid)
- `publisher_normal.py`: benign traffic generator
- `publisher_attacker.py`: attacker traffic generator (flood/burst/jitter)
- `monitor_subscriber.py`: live counters on raw/clean/decision topics
- `evaluate_logs.py`: confusion-matrix style metrics from CSV logs
- `requirements.txt`: Python dependencies

Runtime policy and state extraction are aligned with `RLenv` in `MQTT_RL.py`.

## 1) Install dependencies on each Pi

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

On RPi5, also install broker:

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

## 2) Start MQTTSec on RPi5 (broker host)

Run in rule mode first:

```bash
python3 mqttsec_runtime.py \
  --broker-host 127.0.0.1 \
  --broker-port 1883 \
  --ingress-topic sensors/raw \
  --clean-topic sensors/clean \
  --decision-topic mqttsec/decision \
  --mode rule \
  --threshold1 5 \
  --republish-warn \
  --log-file mqttsec_decisions.csv
```

If you have a pickled model with `predict([[timedelta, msg_id, window_size]])`:

```bash
python3 mqttsec_runtime.py \
  --broker-host 127.0.0.1 \
  --mode hybrid \
  --model-path ./your_model.pkl \
  --republish-warn
```

## 3) Start monitoring (RPi5 or laptop)

```bash
python3 monitor_subscriber.py \
  --broker-host <RPI5_IP> \
  --raw-topic sensors/raw \
  --clean-topic sensors/clean \
  --decision-topic mqttsec/decision
```

## 4) Start normal publisher (RPi4-A)

```bash
python3 publisher_normal.py \
  --broker-host <RPI5_IP> \
  --topic sensors/raw \
  --source-id pub_normal \
  --qos 1 \
  --interval-min 1.0 \
  --interval-max 2.0 \
  --window-size 2
```

## 5) Start attacker publisher (RPi4-B)

Flood mode:

```bash
python3 publisher_attacker.py \
  --broker-host <RPI5_IP> \
  --topic sensors/raw \
  --source-id pub_attack \
  --mode flood \
  --rate 150 \
  --window-size 8 \
  --payload-bytes 512
```

Burst mode:

```bash
python3 publisher_attacker.py \
  --broker-host <RPI5_IP> \
  --mode burst \
  --burst-size 300 \
  --burst-pause 2.0
```

## 6) Evaluate detection performance

After a run, on RPi5 where `mqttsec_decisions.csv` exists:

```bash
python3 evaluate_logs.py --csv mqttsec_decisions.csv --positive-actions decline
```

Treat both warn and decline as attack detection:

```bash
python3 evaluate_logs.py --csv mqttsec_decisions.csv --positive-actions decline,warn
```

## Notes

- Both publishers include a `label` field (`normal` / `attack`) so evaluation can compute TP/FP/FN/TN.
- Runtime publishes decisions to `mqttsec/decision` as JSON events.
- By default, declined messages are dropped and never republished to clean topic.
- If your attacker rate is too high, lower `--rate` to avoid saturating the broker or Wi-Fi.
