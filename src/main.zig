const std = @import("std");
const process = std.process;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const wasm = std.wasm;

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

    var i: u32 = 0;

    const magic = module_bytes[i..][0..4];
    i += 4;
    if (!mem.eql(u8, magic, "\x00asm")) return error.NotWasm;

    const version = mem.readIntLittle(u32, module_bytes[i..][0..4]);
    i += 4;
    if (version != 1) return error.BadWasmVersion;

    var section_starts = [1]u32{0} ** section_count;

    while (i < module_bytes.len) {
        const section_id = @intToEnum(wasm.Section, module_bytes[i]);
        i += 1;
        const section_len = readVarInt(module_bytes, &i, u32);
        section_starts[@enumToInt(section_id)] = i;
        i += section_len;
    }

    // Count the imported functions so we can correct function references.
    const imports = i: {
        i = section_starts[@enumToInt(wasm.Section.import)];
        const imports_len = readVarInt(module_bytes, &i, u32);
        const imports = try arena.alloc(Import, imports_len);
        for (imports) |*imp| {
            const mod_name = readName(module_bytes, &i);
            const sym_name = readName(module_bytes, &i);
            const desc = readVarInt(module_bytes, &i, wasm.ExternalKind);
            switch (desc) {
                .function => {
                    const type_idx = readVarInt(module_bytes, &i, u32);
                    _ = type_idx;
                },
                .table => unreachable,
                .memory => unreachable,
                .global => unreachable,
            }
            imp.* = .{
                .mod_name = mod_name,
                .sym_name = sym_name,
            };
        }
        break :i imports;
    };

    // Find _start in the exports
    const start_fn_idx = i: {
        i = section_starts[@enumToInt(wasm.Section.@"export")];
        var count = readVarInt(module_bytes, &i, u32);
        while (count > 0) : (count -= 1) {
            const name = readName(module_bytes, &i);
            const desc = readVarInt(module_bytes, &i, wasm.ExternalKind);
            const index = readVarInt(module_bytes, &i, u32);
            if (mem.eql(u8, name, "_start") and desc == .function) {
                break :i index;
            }
        }
        return error.StartFunctionNotFound;
    };

    // Map function indexes to offsets into the module and type index.
    const functions = f: {
        var code_i: u32 = section_starts[@enumToInt(wasm.Section.code)];
        var func_i: u32 = section_starts[@enumToInt(wasm.Section.function)];
        const codes_len = readVarInt(module_bytes, &code_i, u32);
        const funcs_len = readVarInt(module_bytes, &func_i, u32);
        assert(codes_len == funcs_len);
        const functions = try arena.alloc(Function, funcs_len);
        for (functions) |*func| {
            const size = readVarInt(module_bytes, &code_i, u32);
            func.* = .{
                .code = code_i,
                .type_idx = readVarInt(module_bytes, &func_i, u32),
            };
            code_i += size;
        }
        break :f functions;
    };

    // Map type indexes to offsets into the module.
    const types = t: {
        i = section_starts[@enumToInt(wasm.Section.type)];
        const types_len = readVarInt(module_bytes, &i, u32);
        const types = try arena.alloc(u32, types_len);
        for (types) |*ty| {
            ty.* = i;
            assert(module_bytes[i] == 0x60);
            i += 1;
            const param_count = readVarInt(module_bytes, &i, u32);
            i += param_count;
            const return_count = readVarInt(module_bytes, &i, u32);
            i += return_count;
        }
        break :t types;
    };

    // Allocate and initialize globals.
    const globals = g: {
        i = section_starts[@enumToInt(wasm.Section.global)];
        const globals_len = readVarInt(module_bytes, &i, u32);
        const globals = try arena.alloc(Value, globals_len);
        for (globals) |*global| {
            const content_type = readVarInt(module_bytes, &i, wasm.Valtype);
            const mutability = readVarInt(module_bytes, &i, Mutability);
            assert(mutability == .@"var");
            assert(content_type == .i32);
            const opcode = @intToEnum(wasm.Opcode, module_bytes[i]);
            i += 1;
            assert(opcode == .i32_const);
            const init = readVarInt(module_bytes, &i, i32);
            global.* = .{ .i32 = init };
        }
        break :g globals;
    };

    // Allocate and initialize memory.
    const memory = m: {
        i = section_starts[@enumToInt(wasm.Section.memory)];
        const memories_len = readVarInt(module_bytes, &i, u32);
        if (memories_len != 1) return error.UnexpectedMemoryCount;
        const flags = readVarInt(module_bytes, &i, u32);
        _ = flags;
        const initial = readVarInt(module_bytes, &i, u32);
        const memory = try gpa.alloc(u8, initial);
        break :m memory;
    };

    var exec: Exec = .{
        .section_starts = section_starts,
        .module_bytes = module_bytes,
        .stack_top = 0,
        .functions = functions,
        .types = types,
        .globals = globals,
        .memory = memory,
        .imports = imports,
    };
    exec.initCall(start_fn_idx);
    exec.run();
}

const section_count = @typeInfo(wasm.Section).Enum.fields.len;
var stack: [1 << 10]Value = undefined;

const Mutability = enum { @"const", @"var" };

const Function = struct {
    /// Index to start of code in module_bytes.
    code: u32,
    /// Index into types.
    type_idx: u32,
};

const Import = struct {
    sym_name: []const u8,
    mod_name: []const u8,
};

const Exec = struct {
    section_starts: [section_count]u32,
    stack_top: u32,
    module_bytes: []const u8,
    current_frame: Frame = Frame.terminus(),
    functions: []const Function,
    /// Type index to start of type in module_bytes.
    types: []const u32,
    globals: []Value,
    memory: []u8,
    imports: []const Import,

    fn initCall(e: *Exec, fn_id: u32) void {
        if (fn_id < e.imports.len) {
            const imp = e.imports[fn_id];
            if (mem.eql(u8, imp.sym_name, "fd_prestat_get")) {
                @panic("TODO implement fd_prestat_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_prestat_dir_name")) {
                @panic("TODO implement fd_prestat_dir_name");
            } else if (mem.eql(u8, imp.sym_name, "proc_exit")) {
                @panic("TODO implement proc_exit");
            } else if (mem.eql(u8, imp.sym_name, "args_sizes_get")) {
                e.stack_top -= 2;
                e.push(Value, .{ .u32 = wasi_args_sizes_get(
                    stack[e.stack_top + 1].u32,
                    stack[e.stack_top + 2].u32,
                ) });
            } else if (mem.eql(u8, imp.sym_name, "args_get")) {
                @panic("TODO implement args_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_close")) {
                @panic("TODO implement fd_close");
            } else if (mem.eql(u8, imp.sym_name, "fd_read")) {
                @panic("TODO implement fd_read");
            } else if (mem.eql(u8, imp.sym_name, "fd_filestat_get")) {
                @panic("TODO implement fd_filestat_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_filestat_set_size")) {
                @panic("TODO implement fd_filestat_set_size");
            } else if (mem.eql(u8, imp.sym_name, "fd_pwrite")) {
                @panic("TODO implement fd_pwrite");
            } else if (mem.eql(u8, imp.sym_name, "random_get")) {
                @panic("TODO implement random_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_filestat_set_times")) {
                @panic("TODO implement fd_filestat_set_times");
            } else if (mem.eql(u8, imp.sym_name, "environ_sizes_get")) {
                @panic("TODO implement environ_sizes_get");
            } else if (mem.eql(u8, imp.sym_name, "environ_get")) {
                @panic("TODO implement environ_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_fdstat_get")) {
                @panic("TODO implement fd_fdstat_get");
            } else if (mem.eql(u8, imp.sym_name, "path_filestat_get")) {
                @panic("TODO implement path_filestat_get");
            } else if (mem.eql(u8, imp.sym_name, "path_create_directory")) {
                @panic("TODO implement path_create_directory");
            } else if (mem.eql(u8, imp.sym_name, "path_rename")) {
                @panic("TODO implement path_rename");
            } else if (mem.eql(u8, imp.sym_name, "fd_readdir")) {
                @panic("TODO implement fd_readdir");
            } else if (mem.eql(u8, imp.sym_name, "fd_write")) {
                @panic("TODO implement fd_write");
            } else if (mem.eql(u8, imp.sym_name, "path_open")) {
                @panic("TODO implement path_open");
            } else if (mem.eql(u8, imp.sym_name, "clock_time_get")) {
                @panic("TODO implement clock_time_get");
            } else if (mem.eql(u8, imp.sym_name, "fd_pread")) {
                @panic("TODO implement fd_pread");
            } else if (mem.eql(u8, imp.sym_name, "path_remove_directory")) {
                @panic("TODO implement path_remove_directory");
            } else if (mem.eql(u8, imp.sym_name, "path_unlink_file")) {
                @panic("TODO implement path_unlink_file");
            } else {
                std.debug.panic("unhandled import: {s}", .{imp.sym_name});
            }
        }
        const fn_idx = fn_id - @intCast(u32, e.imports.len);
        const module_bytes = e.module_bytes;
        const func = e.functions[fn_idx];
        var i: u32 = e.types[func.type_idx];
        assert(module_bytes[i] == 0x60);
        i += 1;
        const param_count = readVarInt(module_bytes, &i, u32);
        i += param_count;
        const return_count = readVarInt(module_bytes, &i, u32);
        i += return_count;
        std.log.debug("fn_idx: {d}, type_idx: {d}, param_count: {d}, return_count: {d}", .{
            fn_idx, func.type_idx, param_count, return_count,
        });

        const locals_begin = e.stack_top - param_count;

        i = func.code;
        var locals_count: u32 = 0;
        var local_sets_count = readVarInt(module_bytes, &i, u32);
        while (local_sets_count > 0) : (local_sets_count -= 1) {
            const current_count = readVarInt(module_bytes, &i, u32);
            const local_type = readVarInt(module_bytes, &i, u32);
            _ = local_type;
            locals_count += current_count;
        }

        // Push zeroed locals to stack
        mem.set(Value, stack[e.stack_top..][0..locals_count], Value{ .v128 = 0 });
        e.stack_top += locals_count;
        e.push(Frame, e.current_frame);

        e.current_frame = .{
            .fn_idx = fn_idx,
            .pc = i,
            .stack_begin = e.stack_top,
            .locals_begin = locals_begin,
        };
    }

    fn push(e: *Exec, comptime T: type, value: T) void {
        comptime assert(@sizeOf(T) == 16);
        stack[e.stack_top] = @bitCast(Value, value);
        e.stack_top += 1;
    }

    fn pop(e: *Exec) Value {
        e.stack_top -= 1;
        return stack[e.stack_top + 1];
    }

    fn run(e: *Exec) noreturn {
        const module_bytes = e.module_bytes;
        const pc = &e.current_frame.pc;
        while (true) {
            const op = @intToEnum(wasm.Opcode, module_bytes[pc.*]);
            pc.* += 1;
            std.log.debug("stack_top={d} pc={d}, op={s}", .{
                stack[e.stack_top].i32, pc.*, @tagName(op),
            });
            switch (op) {
                .@"unreachable" => @panic("unreachable"),
                .nop => {},
                .block => {
                    if (module_bytes[pc.*] == 0x40) {
                        pc.* += 1;
                    } else {
                        const valtype = readVarInt(module_bytes, pc, u32);
                        _ = valtype;
                    }
                },
                .loop => @panic("unhandled opcode: loop"),
                .@"if" => @panic("unhandled opcode: if"),
                .@"else" => @panic("unhandled opcode: else"),
                .end => {},
                .br => @panic("unhandled opcode: br"),
                .br_if => @panic("unhandled opcode: br_if"),
                .br_table => @panic("unhandled opcode: br_table"),
                .@"return" => @panic("unhandled opcode: return"),
                .call => {
                    const fn_id = readVarInt(module_bytes, pc, u32);
                    e.initCall(fn_id);
                },
                .call_indirect => @panic("unhandled opcode: call_indirect"),
                .drop => @panic("unhandled opcode: drop"),
                .select => @panic("unhandled opcode: select"),
                .local_get => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    const val = stack[idx + e.current_frame.locals_begin];
                    e.push(Value, val);
                },
                .local_set => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    stack[idx + e.current_frame.locals_begin] = e.pop();
                },
                .local_tee => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    stack[idx + e.current_frame.locals_begin] = stack[e.stack_top];
                },
                .global_get => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    e.push(Value, e.globals[idx]);
                },
                .global_set => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    e.globals[idx] = e.pop();
                },
                .i32_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .i32 = mem.readIntLittle(i32, e.memory[offset..][0..4]) });
                },
                .i64_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .i64 = mem.readIntLittle(i64, e.memory[offset..][0..8]) });
                },
                .f32_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u32, e.memory[offset..][0..4]);
                    e.push(Value, .{ .f32 = @bitCast(f32, int) });
                },
                .f64_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u64, e.memory[offset..][0..8]);
                    e.push(Value, .{ .f64 = @bitCast(f64, int) });
                },
                .i32_load8_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .i32 = @bitCast(i8, e.memory[offset]) });
                },
                .i32_load8_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .u32 = e.memory[offset] });
                },
                .i32_load16_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i16, e.memory[offset..][0..2]);
                    e.push(Value, .{ .i32 = int });
                },
                .i32_load16_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u16, e.memory[offset..][0..2]);
                    e.push(Value, .{ .u32 = int });
                },
                .i64_load8_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .i64 = @bitCast(i8, e.memory[offset]) });
                },
                .i64_load8_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(Value, .{ .u64 = e.memory[offset] });
                },
                .i64_load16_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i16, e.memory[offset..][0..2]);
                    e.push(Value, .{ .i64 = int });
                },
                .i64_load16_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u16, e.memory[offset..][0..2]);
                    e.push(Value, .{ .u64 = int });
                },
                .i64_load32_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i32, e.memory[offset..][0..4]);
                    e.push(Value, .{ .i64 = int });
                },
                .i64_load32_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u32, e.memory[offset..][0..4]);
                    e.push(Value, .{ .u64 = int });
                },
                .i32_store => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(i32, e.memory[offset..][0..4], e.pop().i32);
                },
                .i64_store => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(i64, e.memory[offset..][0..8], e.pop().i64);
                },
                .f32_store => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = @bitCast(u32, e.pop().f32);
                    mem.writeIntLittle(u32, e.memory[offset..][0..4], int);
                },
                .f64_store => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = @bitCast(u64, e.pop().f64);
                    mem.writeIntLittle(u64, e.memory[offset..][0..8], int);
                },
                .i32_store8 => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.memory[offset] = @truncate(u8, e.pop().u32);
                },
                .i32_store16 => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const small = @truncate(u16, e.pop().u32);
                    mem.writeIntLittle(u16, e.memory[offset..][0..2], small);
                },
                .i64_store8 => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.memory[offset] = @truncate(u8, e.pop().u64);
                },
                .i64_store16 => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const small = @truncate(u16, e.pop().u64);
                    mem.writeIntLittle(u16, e.memory[offset..][0..2], small);
                },
                .i64_store32 => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const small = @truncate(u32, e.pop().u64);
                    mem.writeIntLittle(u32, e.memory[offset..][0..4], small);
                },
                .memory_size => {},
                .memory_grow => {},
                .i32_const => {
                    const x = readVarInt(module_bytes, pc, i32);
                    e.push(Value, .{ .i32 = x });
                },
                .i64_const => {
                    const x = readVarInt(module_bytes, pc, i64);
                    e.push(Value, .{ .i64 = x });
                },
                .f32_const => {
                    const x = readFloat32(module_bytes, pc);
                    e.push(Value, .{ .f32 = x });
                },
                .f64_const => {
                    const x = readFloat64(module_bytes, pc);
                    e.push(Value, .{ .f64 = x });
                },
                .i32_eqz => {
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 == 0);
                },
                .i32_eq => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 == rhs.i32);
                },
                .i32_ne => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 != rhs.i32);
                },
                .i32_lt_s => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 < rhs.i32);
                },
                .i32_lt_u => {
                    const rhs = e.pop();
                    stack[e.stack_top].u32 = @boolToInt(stack[e.stack_top].u32 < rhs.u32);
                },
                .i32_gt_s => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 > rhs.i32);
                },
                .i32_gt_u => {
                    const rhs = e.pop();
                    stack[e.stack_top].u32 = @boolToInt(stack[e.stack_top].u32 > rhs.u32);
                },
                .i32_le_s => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 <= rhs.i32);
                },
                .i32_le_u => {
                    const rhs = e.pop();
                    stack[e.stack_top].u32 = @boolToInt(stack[e.stack_top].u32 <= rhs.u32);
                },
                .i32_ge_s => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 = @boolToInt(stack[e.stack_top].i32 >= rhs.i32);
                },
                .i32_ge_u => {
                    const rhs = e.pop();
                    stack[e.stack_top].u32 = @boolToInt(stack[e.stack_top].u32 >= rhs.u32);
                },
                .i64_eqz => @panic("unhandled opcode: i64_eqz"),
                .i64_eq => @panic("unhandled opcode: i64_eq"),
                .i64_ne => @panic("unhandled opcode: i64_ne"),
                .i64_lt_s => @panic("unhandled opcode: i64_lt_s"),
                .i64_lt_u => @panic("unhandled opcode: i64_lt_u"),
                .i64_gt_s => @panic("unhandled opcode: i64_gt_s"),
                .i64_gt_u => @panic("unhandled opcode: i64_gt_u"),
                .i64_le_s => @panic("unhandled opcode: i64_le_s"),
                .i64_le_u => @panic("unhandled opcode: i64_le_u"),
                .i64_ge_s => @panic("unhandled opcode: i64_ge_s"),
                .i64_ge_u => @panic("unhandled opcode: i64_ge_u"),
                .f32_eq => @panic("unhandled opcode: f32_eq"),
                .f32_ne => @panic("unhandled opcode: f32_ne"),
                .f32_lt => @panic("unhandled opcode: f32_lt"),
                .f32_gt => @panic("unhandled opcode: f32_gt"),
                .f32_le => @panic("unhandled opcode: f32_le"),
                .f32_ge => @panic("unhandled opcode: f32_ge"),
                .f64_eq => @panic("unhandled opcode: f64_eq"),
                .f64_ne => @panic("unhandled opcode: f64_ne"),
                .f64_lt => @panic("unhandled opcode: f64_lt"),
                .f64_gt => @panic("unhandled opcode: f64_gt"),
                .f64_le => @panic("unhandled opcode: f64_le"),
                .f64_ge => @panic("unhandled opcode: f64_ge"),
                .i32_clz => @panic("unhandled opcode: i32_clz"),
                .i32_ctz => @panic("unhandled opcode: i32_ctz"),
                .i32_popcnt => @panic("unhandled opcode: i32_popcnt"),
                .i32_add => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 +%= rhs.i32;
                },
                .i32_sub => {
                    const rhs = e.pop();
                    stack[e.stack_top].i32 -%= rhs.i32;
                },
                .i32_mul => @panic("unhandled opcode: i32_mul"),
                .i32_div_s => @panic("unhandled opcode: i32_div_s"),
                .i32_div_u => @panic("unhandled opcode: i32_div_u"),
                .i32_rem_s => @panic("unhandled opcode: i32_rem_s"),
                .i32_rem_u => @panic("unhandled opcode: i32_rem_u"),
                .i32_and => @panic("unhandled opcode: i32_and"),
                .i32_or => @panic("unhandled opcode: i32_or"),
                .i32_xor => @panic("unhandled opcode: i32_xor"),
                .i32_shl => @panic("unhandled opcode: i32_shl"),
                .i32_shr_s => @panic("unhandled opcode: i32_shr_s"),
                .i32_shr_u => @panic("unhandled opcode: i32_shr_u"),
                .i32_rotl => @panic("unhandled opcode: i32_rotl"),
                .i32_rotr => @panic("unhandled opcode: i32_rotr"),
                .i64_clz => @panic("unhandled opcode: i64_clz"),
                .i64_ctz => @panic("unhandled opcode: i64_ctz"),
                .i64_popcnt => @panic("unhandled opcode: i64_popcnt"),
                .i64_add => @panic("unhandled opcode: i64_add"),
                .i64_sub => @panic("unhandled opcode: i64_sub"),
                .i64_mul => @panic("unhandled opcode: i64_mul"),
                .i64_div_s => @panic("unhandled opcode: i64_div_s"),
                .i64_div_u => @panic("unhandled opcode: i64_div_u"),
                .i64_rem_s => @panic("unhandled opcode: i64_rem_s"),
                .i64_rem_u => @panic("unhandled opcode: i64_rem_u"),
                .i64_and => @panic("unhandled opcode: i64_and"),
                .i64_or => @panic("unhandled opcode: i64_or"),
                .i64_xor => @panic("unhandled opcode: i64_xor"),
                .i64_shl => @panic("unhandled opcode: i64_shl"),
                .i64_shr_s => @panic("unhandled opcode: i64_shr_s"),
                .i64_shr_u => @panic("unhandled opcode: i64_shr_u"),
                .i64_rotl => @panic("unhandled opcode: i64_rotl"),
                .i64_rotr => @panic("unhandled opcode: i64_rotr"),
                .f32_abs => @panic("unhandled opcode: f32_abs"),
                .f32_neg => @panic("unhandled opcode: f32_neg"),
                .f32_ceil => @panic("unhandled opcode: f32_ceil"),
                .f32_floor => @panic("unhandled opcode: f32_floor"),
                .f32_trunc => @panic("unhandled opcode: f32_trunc"),
                .f32_nearest => @panic("unhandled opcode: f32_nearest"),
                .f32_sqrt => @panic("unhandled opcode: f32_sqrt"),
                .f32_add => @panic("unhandled opcode: f32_add"),
                .f32_sub => @panic("unhandled opcode: f32_sub"),
                .f32_mul => @panic("unhandled opcode: f32_mul"),
                .f32_div => @panic("unhandled opcode: f32_div"),
                .f32_min => @panic("unhandled opcode: f32_min"),
                .f32_max => @panic("unhandled opcode: f32_max"),
                .f32_copysign => @panic("unhandled opcode: f32_copysign"),
                .f64_abs => @panic("unhandled opcode: f64_abs"),
                .f64_neg => @panic("unhandled opcode: f64_neg"),
                .f64_ceil => @panic("unhandled opcode: f64_ceil"),
                .f64_floor => @panic("unhandled opcode: f64_floor"),
                .f64_trunc => @panic("unhandled opcode: f64_trunc"),
                .f64_nearest => @panic("unhandled opcode: f64_nearest"),
                .f64_sqrt => @panic("unhandled opcode: f64_sqrt"),
                .f64_add => @panic("unhandled opcode: f64_add"),
                .f64_sub => @panic("unhandled opcode: f64_sub"),
                .f64_mul => @panic("unhandled opcode: f64_mul"),
                .f64_div => @panic("unhandled opcode: f64_div"),
                .f64_min => @panic("unhandled opcode: f64_min"),
                .f64_max => @panic("unhandled opcode: f64_max"),
                .f64_copysign => @panic("unhandled opcode: f64_copysign"),
                .i32_wrap_i64 => @panic("unhandled opcode: i32_wrap_i64"),
                .i32_trunc_f32_s => @panic("unhandled opcode: i32_trunc_f32_s"),
                .i32_trunc_f32_u => @panic("unhandled opcode: i32_trunc_f32_u"),
                .i32_trunc_f64_s => @panic("unhandled opcode: i32_trunc_f64_s"),
                .i32_trunc_f64_u => @panic("unhandled opcode: i32_trunc_f64_u"),
                .i64_extend_i32_s => @panic("unhandled opcode: i64_extend_i32_s"),
                .i64_extend_i32_u => @panic("unhandled opcode: i64_extend_i32_u"),
                .i64_trunc_f32_s => @panic("unhandled opcode: i64_trunc_f32_s"),
                .i64_trunc_f32_u => @panic("unhandled opcode: i64_trunc_f32_u"),
                .i64_trunc_f64_s => @panic("unhandled opcode: i64_trunc_f64_s"),
                .i64_trunc_f64_u => @panic("unhandled opcode: i64_trunc_f64_u"),
                .f32_convert_i32_s => @panic("unhandled opcode: f32_convert_i32_s"),
                .f32_convert_i32_u => @panic("unhandled opcode: f32_convert_i32_u"),
                .f32_convert_i64_s => @panic("unhandled opcode: f32_convert_i64_s"),
                .f32_convert_i64_u => @panic("unhandled opcode: f32_convert_i64_u"),
                .f32_demote_f64 => @panic("unhandled opcode: f32_demote_f64"),
                .f64_convert_i32_s => @panic("unhandled opcode: f64_convert_i32_s"),
                .f64_convert_i32_u => @panic("unhandled opcode: f64_convert_i32_u"),
                .f64_convert_i64_s => @panic("unhandled opcode: f64_convert_i64_s"),
                .f64_convert_i64_u => @panic("unhandled opcode: f64_convert_i64_u"),
                .f64_promote_f32 => @panic("unhandled opcode: f64_promote_f32"),
                .i32_reinterpret_f32 => @panic("unhandled opcode: i32_reinterpret_f32"),
                .i64_reinterpret_f64 => @panic("unhandled opcode: i64_reinterpret_f64"),
                .f32_reinterpret_i32 => @panic("unhandled opcode: f32_reinterpret_i32"),
                .f64_reinterpret_i64 => @panic("unhandled opcode: f64_reinterpret_i64"),
                .i32_extend8_s => @panic("unhandled opcode: i32_extend8_s"),
                .i32_extend16_s => @panic("unhandled opcode: i32_extend16_s"),
                .i64_extend8_s => @panic("unhandled opcode: i64_extend8_s"),
                .i64_extend16_s => @panic("unhandled opcode: i64_extend16_s"),
                .i64_extend32_s => @panic("unhandled opcode: i64_extend32_s"),
                _ => @panic("unhandled opcode"),
            }
        }
    }
};

const Frame = extern struct {
    fn_idx: u32,
    /// Points directly to an instruction in module_bytes.
    pc: u32,
    stack_begin: u32,
    locals_begin: u32,

    pub fn terminus() Frame {
        return @bitCast(Frame, @as(u128, 0));
    }

    pub fn isTerminus(f: Frame) bool {
        return @bitCast(u128, f) == 0;
    }
};

const Value = extern union {
    i32: i32,
    u32: u32,
    i64: i64,
    u64: u64,
    f32: f32,
    f64: f64,
    v128: i128,
};

const SectionPos = struct {
    index: usize,
    len: usize,
};

fn readVarInt(bytes: []const u8, i: *u32, comptime T: type) T {
    switch (@typeInfo(T)) {
        .Enum => |info| {
            const int_result = readVarInt(bytes, i, info.tag_type);
            return @intToEnum(T, int_result);
        },
        else => {},
    }
    const readFn = switch (@typeInfo(T).Int.signedness) {
        .signed => std.leb.readILEB128,
        .unsigned => std.leb.readULEB128,
    };
    var fbs = std.io.fixedBufferStream(bytes);
    fbs.pos = i.*;
    const result = readFn(T, fbs.reader()) catch unreachable;
    i.* = @intCast(u32, fbs.pos);
    return result;
}

fn readName(bytes: []const u8, i: *u32) []const u8 {
    const len = readVarInt(bytes, i, u32);
    const result = bytes[i.*..][0..len];
    i.* += len;
    return result;
}

fn readFloat32(bytes: []const u8, i: *u32) f32 {
    const result_ptr = @ptrCast(*align(1) const f32, bytes[i.*..][0..4]);
    i.* += 4;
    return result_ptr.*;
}

fn readFloat64(bytes: []const u8, i: *u32) f64 {
    const result_ptr = @ptrCast(*align(1) const f64, bytes[i.*..][0..8]);
    i.* += 8;
    return result_ptr.*;
}

fn wasi_args_sizes_get(argc: u32, argv_buf_size: u32) u32 {
    std.log.debug("wasi_args_sizes_get argc={d} argv_buf_size={d}", .{ argc, argv_buf_size });
    @panic("TODO");
}
