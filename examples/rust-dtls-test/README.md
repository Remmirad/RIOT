= Benchmark Settings

- `RUSTFLAGS="-Zlocation-detail=none"`
- `EMBASSY_EXECUTOR_TASK_ARENA_SIZE=2673` (Minimum for `rust-dtls-async-test`)
- `EMBASSY_EXECUTOR_TASK_ARENA_SIZE=2457` (Minimum for `embedded-dtls-test`)
- Set `-Oz` in `RIOT/makefiles/arch/cortexm.inc`
- rustc `1.86.0-nightly (8239a37f9 2025-02-01)`
