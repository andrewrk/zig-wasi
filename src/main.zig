const std = @import("std");
const process = std.process;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;

var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const gpa = general_purpose_allocator.allocator();

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const args = try process.argsAlloc(arena);

    const wasm_file = args[1];
    const ten_moogieboogies = 10 * 1024 * 1024;
    const module_bytes = try fs.cwd().readFileAlloc(arena, wasm_file, ten_moogieboogies);

    var i: usize = 0;

    const magic = module_bytes[i..][0..4];
    i += 4;
    if (!mem.eql(u8, magic, "\x00asm")) return error.NotWasm;

    const version = mem.readIntLittle(u32, module_bytes[i..][0..4]);
    i += 4;
    if (version != 1) return error.BadWasmVersion;

    var sections = [1]SectionPos{.{
        .index = 0,
        .len = 0,
    }} ** @typeInfo(std.wasm.Section).Enum.fields.len;

    while (i < module_bytes.len) {
        const section_id = @intToEnum(std.wasm.Section, module_bytes[i]);
        i += 1;
        const section_len = readVarInt(module_bytes, &i, u32);
        sections[@enumToInt(section_id)] = .{
            .index = i,
            .len = section_len,
        };
        i += section_len;
    }

    for (sections) |pos, index| {
        if (pos.len == 0) continue;
        std.debug.print("{s}: pos={d}, len={d}\n", .{
            @tagName(@intToEnum(std.wasm.Section, index)), pos.index, pos.len,
        });
    }
}

const SectionPos = struct {
    index: usize,
    len: usize,
};

fn readVarInt(bytes: []const u8, i: *usize, comptime T: type) T {
    const readFn = switch (@typeInfo(T).Int.signedness) {
        .signed => std.leb.readILEB128,
        .unsigned => std.leb.readULEB128,
    };
    var fbs = std.io.fixedBufferStream(bytes);
    fbs.pos = i.*;
    const result = readFn(T, fbs.reader()) catch unreachable;
    i.* = fbs.pos;
    return result;
}
