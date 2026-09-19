# cfl-corpus — ClusterFuzzLite storage branch (spore-peer)

Corpus persistence for the Rust p2p decoder fuzzing workflows
(.github/workflows/cflite_*.yml). Structure per the CFL docs:

    /corpus/<fuzz_target>/   — corpus files, one directory per fuzzer

Written by the batch and prune runs. Do not edit by hand: every push
here is machine-generated corpus state, and git history IS the
retention mechanism — unlike run artifacts, nothing here expires
after 90 days.
