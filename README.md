To Run Tests:
<br>
```sh mqtt-test.sh```

## Testbed (Fig. 21)

| Device | Script | Clients |
|---|---|---|
| RPi 4 #1 | `python3 benign_publisher.py --broker <broker-ip>` | 0–9 benign |
| RPi 4 #2 | `python3 attacker_publisher.py --broker <broker-ip>` | 10–14 attackers |
| RPi 5 | `python3 mqttsec_broker.py --epochs 60 --retrain 15` (next to Mosquitto) | — |

Start the attacker publisher and the broker at about the same time.

### Evolving attack campaigns

The attacker publisher changes tactics every 15 epochs (one epoch = 10 episodes × 2 s = 20 s), so the traffic the RF sees keeps drifting away from what it was trained on (Sec. 6.3.2). During each campaign the share of evasive messages grows from 15 % to 75 %. Campaigns alternate between:

- **A**: a compact small-payload QoS 0 flood (34 B, tδ < 30 ms)
- **B**: a low-rate, heavy-payload QoS 1 flood (660–760 B, tδ 65–110 ms)

Eq. 5 and Eq. 6 still decline every evasive message, so attackers keep a return of 0. Only the RF state is fooled until the next retrain, which produces the error and ε sawtooth in Fig. 21(b).

- `--campaign-epochs N`: change tactic every N epochs. Keep it equal to the broker's `--retrain`.
- `--no-campaigns`: use fixed attack tactics only.
