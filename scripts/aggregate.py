#!/usr/bin/env python3
"""Aggregate raw JSON metrics into CSV and plot the four figures."""

import argparse
import glob
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load(paths):
    runs = []
    for p in paths:
        with open(p) as f:
            data = json.load(f)
        if isinstance(data, dict):
            for m in data.values():
                m["_source"] = p
                runs.append(m)
        else:
            for m in data:
                m["_source"] = p
                runs.append(m)
    return runs


def fig_share_count(runs, outdir):
    """Adversary share count vs |R_mid|.

    In the current controller the reader set size is not recorded; this
    placeholder plots the observed distinct_shares_verified per node so
    the plot harness is ready when the controller is instrumented.
    """
    fig, ax = plt.subplots(figsize=(6, 4))
    xs, ys = [], []
    for m in runs:
        if m.get("delivered"):
            xs.append(m["node_id"])
            ys.append(m.get("distinct_shares_verified", 0))
    if xs:
        ax.scatter(xs, ys)
    ax.set_xlabel("node id")
    ax.set_ylabel("distinct verified shares")
    ax.set_title("Adversary share count (placeholder — instrument |R_mid|)")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "share_count.pdf"))
    plt.close(fig)


def fig_bytes(runs, outdir):
    by_n = defaultdict(list)
    for m in runs:
        # n is not in metrics; skip if absent
        n = m.get("n")
        if n is None:
            continue
        total = m.get("bytes_sent", 0) + m.get("bytes_received", 0)
        by_n[n].append(total)
    if not by_n:
        return
    xs = sorted(by_n)
    ys = [sum(by_n[n]) / len(by_n[n]) for n in xs]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(xs, ys, marker="o")
    ax.set_xlabel("n")
    ax.set_ylabel("bytes per broadcast")
    ax.set_title("Communication vs n")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "bytes.pdf"))
    plt.close(fig)


def fig_latency(runs, outdir):
    lat = [m["recon_done_at_ns"] for m in runs if m.get("recon_done_at_ns")]
    if not lat:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist([x / 1e6 for x in lat], bins=20)
    ax.set_xlabel("reconstruction latency (ms)")
    ax.set_ylabel("count")
    ax.set_title("Latency distribution")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "latency.pdf"))
    plt.close(fig)


def fig_state(runs, outdir):
    ids = [m["node_id"] for m in runs if m.get("delivered")]
    foreign = [m.get("foreign_shares_after_cleanup", 0) for m in runs if m.get("delivered")]
    if not ids:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(ids, foreign)
    ax.set_xlabel("reader id")
    ax.set_ylabel("foreign shares after cleanup")
    ax.set_title("Post-completion state audit (should be zero)")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "state.pdf"))
    plt.close(fig)


def write_csv(runs, outdir):
    import csv
    fields = [
        "node_id", "delivered", "delivered_hash", "distinct_shares_verified",
        "bytes_sent", "bytes_received", "recon_done_at_ns",
        "foreign_shares_after_cleanup", "pending_after_cleanup",
    ]
    path = os.path.join(outdir, "aggregate.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for m in runs:
            w.writerow(m)
    print(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="data/*.json")
    ap.add_argument("--outdir", default="figures")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    runs = load(glob.glob(args.glob))
    print(f"loaded {len(runs)} node-metrics records")
    write_csv(runs, args.outdir)
    fig_share_count(runs, args.outdir)
    fig_bytes(runs, args.outdir)
    fig_latency(runs, args.outdir)
    fig_state(runs, args.outdir)


if __name__ == "__main__":
    main()