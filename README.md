# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Status

It passes the official zig behavior tests compiled to wasm32-wasi:

```
$ stage3/bin/zig test ../test/behavior.zig -target wasm32-wasi -OReleaseSmall -I../test --test-cmd ~/dev/zig-wasi/zig-out/bin/zig-wasi --test-cmd-bin
1355 passed; 116 skipped; 0 failed.
```

On the actual WASI build of Zig, the next step is to implement some more WASI
functions:

```
$ zig-out/bin/zig-wasi ~/Downloads/zig/build-release/wasi/bin/zig.wasm
thread 2370231 panic: TODO
/home/andy/dev/zig-wasi/src/main.zig:1750:5: 0x255928 in wasi_args_get (zig-wasi)
    @panic("TODO");
    ^
/home/andy/dev/zig-wasi/src/main.zig:622:49: 0x22f879 in callImport (zig-wasi)
            e.push(u64, @enumToInt(wasi_args_get(e, argv, argv_buf)));
                                                ^
```

## Inspiration

 * [fengb/wazm](https://github.com/fengb/wazm/)
 * [malcolmstill/zware](https://github.com/malcolmstill/zware)
