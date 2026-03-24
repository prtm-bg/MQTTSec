#!/usr/bin/env python3
import argparse

import pandas as pd


POSITIVE_ACTIONS_DEFAULT = {"decline"}


def classification_from_row(row, positive_actions):
    true_attack = str(row["label"]).lower() == "attack"
    pred_attack = str(row["final_action"]).lower() in positive_actions

    if true_attack and pred_attack:
        return "TP"
    if not true_attack and pred_attack:
        return "FP"
    if true_attack and not pred_attack:
        return "FN"
    return "TN"


def safe_div(n, d):
    return n / d if d else 0.0


def main():
    p = argparse.ArgumentParser(description="Evaluate mqttsec_decisions.csv")
    p.add_argument("--csv", default="mqttsec_decisions.csv")
    p.add_argument(
        "--positive-actions",
        default="decline",
        help="Comma-separated actions treated as ATTACK predictions (e.g. decline,warn)",
    )
    args = p.parse_args()

    positive_actions = {x.strip().lower() for x in args.positive_actions.split(",") if x.strip()}
    if not positive_actions:
        positive_actions = set(POSITIVE_ACTIONS_DEFAULT)

    df = pd.read_csv(args.csv)
    if df.empty:
        print("No rows in CSV.")
        return

    required = {"label", "final_action", "source_id"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing required columns: {sorted(missing)}")

    df["cm"] = df.apply(lambda r: classification_from_row(r, positive_actions), axis=1)

    tp = int((df["cm"] == "TP").sum())
    fp = int((df["cm"] == "FP").sum())
    fn = int((df["cm"] == "FN").sum())
    tn = int((df["cm"] == "TN").sum())

    accuracy = safe_div(tp + tn, tp + fp + fn + tn)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)

    print("=== Global Metrics ===")
    print(f"Rows: {len(df)}")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")

    print("\n=== Actions by Label ===")
    print(pd.crosstab(df["label"], df["final_action"]))

    print("\n=== Per Source Summary ===")
    per_source = df.groupby(["source_id", "label", "final_action"]).size().reset_index(name="count")
    print(per_source.sort_values(["source_id", "count"], ascending=[True, False]).to_string(index=False))


if __name__ == "__main__":
    main()
