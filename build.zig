const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zig-wasi", "src/main.zig");
    exe.linkLibC();
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const c_exe = b.addExecutable("c-wasi", "src/main.c");
    c_exe.linkLibC();
    c_exe.setTarget(target);
    c_exe.setBuildMode(mode);
    c_exe.install();
}
