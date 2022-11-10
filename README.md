# Minimal WASI Interpreter

The purpose of this codebase is to be minimal Zig code that can successfully
build Zig by interpreting a WASI build of Zig.

After it works I plan to translate the code to C using the C backend, and then
maintain the C code upstream in the main Zig repository.

## Status

```
$ zig build -Drelease-fast
$ cd ~/Downloads/zig
$ ~/dev/zig-wasi/zig-out/bin/zig-wasi lib build-release/wasi/bin/zig.wasm build-exe src/main.zig -ofmt=c --name zig2 -lc --pkg-begin build_options build-release/options.zig --pkg-end -target x86_64-linux-musl --color on -Drelease
<executed in 4:21:55 with peak RSS of 3.9 GiB>
$ # manual fixup: copy zig.h to cwd
$ # manual fixup: change include <zig.h> to include "zig.h"
$ # manual fixup: change signature of main to fix compile error
$ clang-15 -c zig2.c -fbracket-depth=512 -Wno-return-type -O2 -march=native
<executed in 2:15 with peak RSS of 1.3 GiB>
```

## Problems

 * It needs to be way, way, way faster.
   - Branching is the current bottleneck. Instead of skipping over code, code
     should be preprocessed with branch targets cached.
   - Within the WASI build of the compiler, a faster allocator should be used.
     Currently it is GeneralPurposeAllocator backed by the WebAssembly page
     allocator.
   - Improving memcpy/memset perf in the interpreter may provide some gains.
 * The manual fixups must be eliminated.
 * The `-target` flag needs to be auto detected somehow. If we use the native
   target with the WASI build of Zig, it targets WASI, but we need it to target
   the host.
   - This can be solved by having the WASI interpreter code detect the host in
     order to pass the correct `-target` flag.

## Inspiration

 * [fengb/wazm](https://github.com/fengb/wazm/)
 * [malcolmstill/zware](https://github.com/malcolmstill/zware)
