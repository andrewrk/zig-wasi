# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Credit where credit is due

Shameless ripoff of [fengb/wazm](https://github.com/fengb/wazm/). Reworked to
ease the transition to a C codebase for the sole purpose of bootstrapping Zig.
