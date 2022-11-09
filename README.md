# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Status

With a hot ZIR cache:

```
$ zig build -Drelease-fast
$ zig-out/bin/zig-wasi ~/Downloads/zig/lib  ~/Downloads/zig/build-release/wasi/bin/zig.wasm build-exe hello.zig -ofmt=c -target x86_64-linux-musl -lc
<executed in 110 seconds>
$ zig run hello.c -lc
Hello, World!
```

## Inspiration

 * [fengb/wazm](https://github.com/fengb/wazm/)
 * [malcolmstill/zware](https://github.com/malcolmstill/zware)
