//! copied from lib/std/io/c_writer.zig, unaudited

const std = @import("std");

pub const CReader = std.io.Reader(*std.c.FILE, std.fs.File.ReadError, cReaderRead);

pub fn cReader(c_file: *std.c.FILE) CReader {
    return .{ .context = c_file };
}

fn cReaderRead(c_file: *std.c.FILE, bytes: []u8) std.fs.File.ReadError!usize {
    const amt_read = std.c.fread(bytes.ptr, 1, bytes.len, c_file);
    if (amt_read >= 0) return amt_read;
    switch (@intToEnum(std.os.E, std.c._errno().*)) {
        .SUCCESS => unreachable,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .AGAIN => unreachable, // this is a blocking API
        .BADF => unreachable, // always a race condition
        .DESTADDRREQ => unreachable, // connect was never called
        .DQUOT => return error.DiskQuota,
        .FBIG => return error.FileTooBig,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .PERM => return error.AccessDenied,
        .PIPE => return error.BrokenPipe,
        else => |err| return std.os.unexpectedErrno(err),
    }
}
