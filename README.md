# CRBB: Reader-Restricted Byzantine Broadcast

This repository contains the implementation, OMNeT++ model, deployment
scripts, and evaluation artifacts for "Reader-Restricted Byzantine
Broadcast with Post-Execution Component-State Confidentiality."

The repository is named `cbrb`; the protocol is referred to as CRBB
throughout.

## Layout

| Path | Contents |
|------|----------|
| `src/` | Rust implementation of CRBB and CRBB-H |
| `src/bin/` | `node` and `controller` binaries |
| `omnetpp/` | OMNeT++ discrete-event model |
| `deploy/gcp/` | Terraform and startup scripts |
| `scripts/` | Aggregation and Byzantine-scenario checks |
| `benches/` | Criterion microbenchmarks |
| `tests/` | Protocol unit tests and 7-node integration test |

## Requirements

- Rust 1.75.0
- OMNeT++ 6.0.3 (prebuilt Linux tarball is sufficient)
- Optional: Terraform 1.5+, `gcloud`, `jq` (deployment)
- Optional: Python 3.11+, `matplotlib` (plots)

## Build and test

    cargo build --release
    cargo test
    cargo bench

## Reproducing the paper

1. Native primitive costs:
       cargo bench --bench crypto --bench crypto_batched

2. Simulation sweeps (from `omnetpp/`):
       source <omnetpp-root>/setenv
       opp_makemake --deep -I. -O out -o crbb-sim
       make
       ./out/clang-release/crbb-sim -u Cmdenv -c Baseline -n .

3. Byzantine-scenario checks:
       python3 scripts/check_byz.py s1 data/s1/*.json

4. Figures:
       python3 scripts/aggregate.py --glob 'data/*.json' --outdir figures/

5. Deployment: see `deploy/gcp/README.md`.

## License

MIT. See `LICENSE`.
