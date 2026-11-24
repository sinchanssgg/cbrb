# CRBB: Reader-Restricted Byzantine Broadcast

Implementation, simulation model, and experimental artifacts for
"Confidentiality-preserving Reliable Byzantine Broadcast."

## Structure

- `src/` — Rust implementation of CRBB
- `benches/` — Criterion microbenchmarks and localhost end-to-end
- `tests/` — protocol unit tests and 7-node integration test
- `omnetpp/` — OMNeT++ discrete-event model
- `deploy/gcp/` — Terraform and startup scripts for GCP deployment
- `scripts/` — metric aggregation and safety parser

## Building

```bash
cargo build --release
```

## Running tests

```bash
cargo test
```

## Benchmarks

```bash
cargo bench
```

## Reproduction

See `deploy/gcp/README.md` for the cloud sweep and `omnetpp/README.md`
for the simulator.