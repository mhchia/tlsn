# Benchmark with tlsn-server-fixture

## Setup
Notary <-> Prover <-> Test Server (tlsn-server-fixture)

## Configurations
In [benchmark.rs](./benchmark.rs)
- `NUM_LOOPS`: notarize for this many times and take the average.
- `DATA_SIZE`: size of the data to be notarized in KB. Now the fixture only supports 1, 4, and 8 KB.
- `NOTARY_MAX_TRANSCRIPT_SIZE`: maximum size of the transcript in KB. Note that
    - This number should be large enough for a larger dataset.
    - This value `max-transcript-size` must be the same one used by notary-server. Otherwise the notary server will reject the transcript.

## Steps to run
### 1. Start tlsn-server-fixture server
At the root level of this repository, run
```sh
cd tlsn/tlsn-server-fixture
PORT=22655 cargo run --release
```
to start the server on port `22655`.

### 2. Start the notary server
First, change the `notarization.max-transcript-size` in `notary-server/config/config.yaml` to be `49152`.

Then, run the following command under `notary-server` folder:
```sh
cd ../../notary-server
cargo run --release
```

### 3. Run the benchmark
```sh
RUST_LOG=debug,yamux=info cargo run --release --example benchmark
```
