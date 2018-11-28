#!/bin/sh
cargo afl build
cargo afl fuzz -i in -o target/fuzz target/debug/csrf-token-fuzz
