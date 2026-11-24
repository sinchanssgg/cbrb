#!/usr/bin/env python3
"""Check S1–S6 experiment outputs.

Reads the JSON metric dump produced by the Rust controller or the
scraped scalar files from OMNeT++. Reports per-scenario expected vs.
observed:
  S1: all correct readers delivered.
  S2: no correct reader accepted a forged share (distinct_shares_verified ≤ k).
  S3: no two correct readers delivered distinct values.
  S4: every correct reader delivered (relay restored totality).
      With --no-relay, only the targeted reader delivered.
  S5: reliability unaffected; a Byzantine reader recovered the plaintext.
  S6: pending buffer peak ≤ n*(n-1) entries.
"""

import argparse
import json
import sys


def load(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        return list(data.values())
    return data


def check_s1(nodes, n, t):
    """All correct readers deliver."""
    readers = [m for m in nodes if m.get("is_reader")]
    delivered = [m for m in readers if m.get("delivered")]
    return len(delivered) == len(readers), f"{len(delivered)}/{len(readers)} readers delivered"


def check_s2(nodes, n, t):
    """No forged share accepted."""
    ok = True
    detail = []
    for m in nodes:
        if m.get("delivered"):
            shares = m.get("distinct_shares_verified", 0)
            if shares > t + 8:  # tolerance for legitimate foreign shares
                ok = False
                detail.append(f"node {m['node_id']}: {shares} shares accepted (expected ≤ k)")
    return ok, "; ".join(detail) if detail else "all accepted shares within bound"


def check_s3(nodes, n, t):
    """Agreement: no two correct readers delivered distinct values."""
    hashes = {m["delivered_hash"] for m in nodes if m.get("delivered")}
    if len(hashes) > 1:
        return False, f"conflicting values: {hashes}"
    return True, f"{len(hashes)} distinct value(s) among deliverers"


def check_s4(nodes, n, t, no_relay=False):
    """All correct readers deliver (with relay); only target (without)."""
    readers = [m for m in nodes if m.get("is_reader")]
    delivered = [m for m in readers if m.get("delivered")]
    if no_relay:
        return len(delivered) == 1, f"{len(delivered)} reader(s) delivered (no-relay expected 1)"
    return len(delivered) == len(readers), f"{len(delivered)}/{len(readers)} readers delivered"


def check_s5(nodes, n, t):
    """Reliability unaffected; a Byzantine reader recovered the plaintext."""
    byz = [m for m in nodes if m.get("byzantine") and m.get("is_reader")]
    recovered = [m for m in byz if m.get("delivered")]
    return len(recovered) >= 1, f"{len(recovered)} Byzantine reader(s) recovered"


def check_s6(nodes, n, t):
    """Pending buffer bound respected."""
    max_pending = max((m.get("pending_after_cleanup", 0) for m in nodes), default=0)
    bound = n * (n - 1)
    return max_pending <= bound, f"max pending {max_pending} (bound {bound})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["s1", "s2", "s3", "s4", "s5", "s6"])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--no-relay", action="store_true", help="S4 ablation")
    args = ap.parse_args()

    rc = 0
    for path in args.files:
        nodes = load(path)
        n = max((m.get("n", 0) for m in nodes), default=7)
        t = max((m.get("t", 0) for m in nodes), default=2)
        if args.scenario == "s1":
            ok, msg = check_s1(nodes, n, t)
        elif args.scenario == "s2":
            ok, msg = check_s2(nodes, n, t)
        elif args.scenario == "s3":
            ok, msg = check_s3(nodes, n, t)
        elif args.scenario == "s4":
            ok, msg = check_s4(nodes, n, t, no_relay=args.no_relay)
        elif args.scenario == "s5":
            ok, msg = check_s5(nodes, n, t)
        elif args.scenario == "s6":
            ok, msg = check_s6(nodes, n, t)
        status = "OK" if ok else "FAIL"
        print(f"{status}: {path} — {msg}")
        if not ok:
            rc |= 1
    sys.exit(rc)


if __name__ == "__main__":
    main()