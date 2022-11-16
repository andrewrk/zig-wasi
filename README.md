# Minimal WASI Interpreter

This codebase contains both a Zig implementation and a C implementation of a
WASI interpreter that is capable of interpreting a WASI build of the Zig
compiler, built with `-Dwasi-bootstrap`, and then optimized with
`wasm-opt -Oz --enable-bulk-memory`.

## Status

It works!

This repository is now used for experimentation while the main development
takes place upstream, currently in the wasi-bootstrap branch, but soon to be
merged into master.

## Inspiration

 * [fengb/wazm](https://github.com/fengb/wazm/)
 * [malcolmstill/zware](https://github.com/malcolmstill/zware)
