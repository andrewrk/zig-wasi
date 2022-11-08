# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Status

It passes the official zig behavior tests compiled to wasm32-wasi:

```
$ stage3/bin/zig test ../test/behavior.zig -target wasm32-wasi -OReleaseSmall -I../test --test-cmd ~/dev/zig-wasi/zig-out/bin/zig-wasi --test-cmd-bin
1354 passed; 116 skipped; 0 failed.
```

Caveat: with the `memory_size`/`memory_grow` test disabled because such
operations are not actually used by a WASI build of the Zig compiler.

On the actual WASI build of the Zig compiler, we hit a crash due to an indirect
call accessing a nonexistent table:

```
$ zig-out/bin/zig-wasi ~/Downloads/zig/build-release/wasi/bin/zig.wasm
thread 2345823 panic: reached unreachable code
/home/andy/Downloads/zig/lib/std/debug.zig:278:14: 0x21ea50 in assert (zig-wasi)
    if (!ok) unreachable; // assertion failure
             ^
/home/andy/dev/zig-wasi/src/main.zig:797:27: 0x220ad2 in run (zig-wasi)
                    assert(table_idx == 0);
                          ^
```


## Credit where credit is due

I used these projects for inspiration:

 * [fengb/wazm](https://github.com/fengb/wazm/)
 * [malcolmstill/zware](https://github.com/malcolmstill/zware)
