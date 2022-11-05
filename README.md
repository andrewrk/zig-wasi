# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Status

It finds the `_start` symbol and then hits a missing opcode:

```

$ zig-out/bin/zig-wasi ~/Downloads/zig/build-release/wasi/bin/zig.wasm
thread 2031647 panic: unhandled opcode: global_get
/home/andy/dev/zig-wasi/src/main.zig:218:32: 0x219d30 in run (zig-wasi)
                .global_get => @panic("unhandled opcode: global_get"),
                               ^
```

## Credit where credit is due

Shameless ripoff of [fengb/wazm](https://github.com/fengb/wazm/). Reworked to
ease the transition to a C codebase for the sole purpose of bootstrapping Zig.
