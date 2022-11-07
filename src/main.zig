const std = @import("std");
const process = std.process;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const wasm = std.wasm;
const wasi = std.os.wasi;
const os = std.os;
const log = std.log;

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

    const cwd = try fs.cwd().openDir(".", .{});
    const cache_dir = try cwd.makeOpenPath("zig1-cache", .{});

    addPreopen(0, "stdin", os.STDIN_FILENO);
    addPreopen(1, "stdout", os.STDOUT_FILENO);
    addPreopen(2, "stderr", os.STDERR_FILENO);
    addPreopen(3, ".", cwd.fd);
    addPreopen(4, "/cwd", cwd.fd);
    addPreopen(5, "/cache", cache_dir.fd);

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
        const initial = readVarInt(module_bytes, &i, u32) * 64 * 1024;
        const memory = try arena.alloc(u8, initial);
        @memset(memory.ptr, 0, memory.len);

        i = section_starts[@enumToInt(wasm.Section.data)];
        var datas_count = readVarInt(module_bytes, &i, u32);
        while (datas_count > 0) : (datas_count -= 1) {
            const mode = readVarInt(module_bytes, &i, u32);
            assert(mode == 0);
            const opcode = @intToEnum(wasm.Opcode, module_bytes[i]);
            i += 1;
            assert(opcode == .i32_const);
            const offset = readVarInt(module_bytes, &i, u32);
            const end = @intToEnum(wasm.Opcode, module_bytes[i]);
            assert(end == .end);
            i += 1;
            const bytes_len = readVarInt(module_bytes, &i, u32);
            mem.copy(u8, memory[offset..], module_bytes[i..][0..bytes_len]);
            i += bytes_len;
        }

        break :m memory;
    };

    frames[0] = .{
        .fn_idx = 0,
        .pc = undefined,
        .stack_begin = undefined,
        .locals_begin = undefined,
        .labels_end = 0,
        .return_arity = 0,
    };

    var exec: Exec = .{
        .module_bytes = module_bytes,
        .stack_top = 0,
        .frames_index = 1,
        .functions = functions,
        .types = types,
        .globals = globals,
        .memory = memory,
        .imports = imports,
        .args = args[1..],
    };
    exec.call(start_fn_idx);
    exec.run();
}

const section_count = @typeInfo(wasm.Section).Enum.fields.len;
var stack: [1000]Value = undefined;
var frames: [1000]Frame = undefined;
var labels: [1000]Label = undefined;

const Frame = struct {
    fn_idx: u32,
    /// Points directly to an instruction in module_bytes.
    pc: u32,
    stack_begin: u32,
    locals_begin: u32,
    labels_end: u32,
    return_arity: u32,
};

const Label = struct {
    /// If it's non-zero then it's a loop and this is the
    /// pc of the instruction after the loop.
    /// If it's zero then it's a block.
    loop_pc: u32,
    block_type: i32,
    stack_top: u32,
};

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
    /// Points to one after the last stack item.
    stack_top: u32,
    frames_index: u32,
    module_bytes: []const u8,
    functions: []const Function,
    /// Type index to start of type in module_bytes.
    types: []const u32,
    globals: []Value,
    memory: []u8,
    imports: []const Import,
    args: []const []const u8,

    fn br(e: *Exec, label_count: u32) void {
        const frame = &frames[e.frames_index];
        //log.debug("br frame.labels_end={d} label_count={d}", .{ frame.labels_end, label_count });
        const pc = &frame.pc;
        const label = labels[frame.labels_end - label_count];

        // Taking a branch unwinds the operand stack up to the height where the
        // targeted structured control instruction was entered
        if (label.block_type >= 0) {
            @panic("loop type gte zero");
        } else if (label.block_type == -0x40) {
            // void
            e.stack_top = label.stack_top;
        } else {
            // one result value
            stack[label.stack_top] = stack[e.stack_top - 1];
            e.stack_top = label.stack_top + 1;
        }

        if (label.loop_pc != 0) {
            pc.* = label.loop_pc;
            frame.labels_end -= label_count - 1;
            return;
        }

        frame.labels_end -= label_count;

        // Skip forward past N end instructions.
        const module_bytes = e.module_bytes;
        var end_count: u32 = label_count;
        while (end_count > 0) {
            const op = @intToEnum(wasm.Opcode, module_bytes[pc.*]);
            //log.debug("skipping over pc={d} op={s}", .{ pc.*, @tagName(op) });
            pc.* += 1;
            switch (op) {
                .block, .loop => {
                    // empirically there are no non-void blocks/loops
                    assert(module_bytes[pc.*] == 0x40);
                    pc.* += 1;
                    end_count += 1;
                },
                .@"if" => @panic("unhandled (parse) opcode: if"),
                .@"else" => @panic("unhandled (parse) opcode: else"),
                .end => {
                    end_count -= 1;
                },

                .@"unreachable",
                .nop,
                .memory_size,
                .memory_grow,
                .i32_eqz,
                .i32_eq,
                .i32_ne,
                .i32_lt_s,
                .i32_lt_u,
                .i32_gt_s,
                .i32_gt_u,
                .i32_le_s,
                .i32_le_u,
                .i32_ge_s,
                .i32_ge_u,
                .i64_eqz,
                .i64_eq,
                .i64_ne,
                .i64_lt_s,
                .i64_lt_u,
                .i64_gt_s,
                .i64_gt_u,
                .i64_le_s,
                .i64_le_u,
                .i64_ge_s,
                .i64_ge_u,
                .f32_eq,
                .f32_ne,
                .f32_lt,
                .f32_gt,
                .f32_le,
                .f32_ge,
                .f64_eq,
                .f64_ne,
                .f64_lt,
                .f64_gt,
                .f64_le,
                .f64_ge,
                .i32_clz,
                .i32_ctz,
                .i32_popcnt,
                .i32_add,
                .i32_sub,
                .i32_mul,
                .i32_div_s,
                .i32_div_u,
                .i32_rem_s,
                .i32_rem_u,
                .i32_and,
                .i32_or,
                .i32_xor,
                .i32_shl,
                .i32_shr_s,
                .i32_shr_u,
                .i32_rotl,
                .i32_rotr,
                .i64_clz,
                .i64_ctz,
                .i64_popcnt,
                .i64_add,
                .i64_sub,
                .i64_mul,
                .i64_div_s,
                .i64_div_u,
                .i64_rem_s,
                .i64_rem_u,
                .i64_and,
                .i64_or,
                .i64_xor,
                .i64_shl,
                .i64_shr_s,
                .i64_shr_u,
                .i64_rotl,
                .i64_rotr,
                .f32_abs,
                .f32_neg,
                .f32_ceil,
                .f32_floor,
                .f32_trunc,
                .f32_nearest,
                .f32_sqrt,
                .f32_add,
                .f32_sub,
                .f32_mul,
                .f32_div,
                .f32_min,
                .f32_max,
                .f32_copysign,
                .f64_abs,
                .f64_neg,
                .f64_ceil,
                .f64_floor,
                .f64_trunc,
                .f64_nearest,
                .f64_sqrt,
                .f64_add,
                .f64_sub,
                .f64_mul,
                .f64_div,
                .f64_min,
                .f64_max,
                .f64_copysign,
                .i32_wrap_i64,
                .i32_trunc_f32_s,
                .i32_trunc_f32_u,
                .i32_trunc_f64_s,
                .i32_trunc_f64_u,
                .i64_extend_i32_s,
                .i64_extend_i32_u,
                .i64_trunc_f32_s,
                .i64_trunc_f32_u,
                .i64_trunc_f64_s,
                .i64_trunc_f64_u,
                .f32_convert_i32_s,
                .f32_convert_i32_u,
                .f32_convert_i64_s,
                .f32_convert_i64_u,
                .f32_demote_f64,
                .f64_convert_i32_s,
                .f64_convert_i32_u,
                .f64_convert_i64_s,
                .f64_convert_i64_u,
                .f64_promote_f32,
                .i32_reinterpret_f32,
                .i64_reinterpret_f64,
                .f32_reinterpret_i32,
                .f64_reinterpret_i64,
                .i32_extend8_s,
                .i32_extend16_s,
                .i64_extend8_s,
                .i64_extend16_s,
                .i64_extend32_s,
                .drop,
                .select,
                .@"return",
                => {},

                .br,
                .br_if,
                .call,
                .local_get,
                .local_set,
                .local_tee,
                .global_get,
                .global_set,
                => {
                    _ = readVarInt(module_bytes, pc, u32);
                },

                .i32_load,
                .i64_load,
                .f32_load,
                .f64_load,
                .i32_load8_s,
                .i32_load8_u,
                .i32_load16_s,
                .i32_load16_u,
                .i64_load8_s,
                .i64_load8_u,
                .i64_load16_s,
                .i64_load16_u,
                .i64_load32_s,
                .i64_load32_u,
                .i32_store,
                .i64_store,
                .f32_store,
                .f64_store,
                .i32_store8,
                .i32_store16,
                .i64_store8,
                .i64_store16,
                .i64_store32,
                .call_indirect,
                => {
                    _ = readVarInt(module_bytes, pc, u32);
                    _ = readVarInt(module_bytes, pc, u32);
                },

                .br_table => @panic("unhandled (parse) opcode: br_table"),

                .f32_const => {
                    pc.* += 4;
                },
                .f64_const => {
                    pc.* += 8;
                },
                .i32_const => {
                    _ = readVarInt(module_bytes, pc, i32);
                },
                .i64_const => {
                    _ = readVarInt(module_bytes, pc, i64);
                },

                _ => @panic("unhandled (parse) opcode"),
            }
        }
    }

    fn call(e: *Exec, fn_id: u32) void {
        if (fn_id < e.imports.len) {
            const imp = e.imports[fn_id];
            return callImport(e, imp);
        }
        const fn_idx = fn_id - @intCast(u32, e.imports.len);
        const module_bytes = e.module_bytes;
        const func = e.functions[fn_idx];
        var i: u32 = e.types[func.type_idx];
        assert(module_bytes[i] == 0x60);
        i += 1;
        const param_count = readVarInt(module_bytes, &i, u32);
        i += param_count;
        const return_arity = readVarInt(module_bytes, &i, u32);
        i += return_arity;

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

        log.debug("fn_idx: {d}, type_idx: {d}, param_count: {d}, return_arity: {d}, locals_begin: {d}, locals_count: {d}", .{
            fn_idx, func.type_idx, param_count, return_arity, locals_begin, locals_count,
        });

        // Push zeroed locals to stack
        mem.set(Value, stack[e.stack_top..][0..locals_count], Value{ .u64 = 0 });
        e.stack_top += locals_count;

        const prev_labels_end = frames[e.frames_index].labels_end;

        e.frames_index += 1;
        frames[e.frames_index] = .{
            .fn_idx = fn_idx,
            .return_arity = return_arity,
            .pc = i,
            .stack_begin = e.stack_top,
            .locals_begin = locals_begin,
            .labels_end = prev_labels_end,
        };
    }

    fn callImport(e: *Exec, imp: Import) void {
        if (mem.eql(u8, imp.sym_name, "fd_prestat_get")) {
            e.stack_top -= 2;
            e.push(.{ .u32 = @enumToInt(wasi_fd_prestat_get(
                e,
                stack[e.stack_top + 0].i32,
                stack[e.stack_top + 1].u32,
            )) });
        } else if (mem.eql(u8, imp.sym_name, "fd_prestat_dir_name")) {
            e.stack_top -= 3;
            e.push(.{ .u32 = @enumToInt(wasi_fd_prestat_dir_name(
                e,
                stack[e.stack_top + 0].i32,
                stack[e.stack_top + 1].u32,
                stack[e.stack_top + 2].u32,
            )) });
        } else if (mem.eql(u8, imp.sym_name, "proc_exit")) {
            std.process.exit(@intCast(u8, e.pop().u32));
            unreachable;
        } else if (mem.eql(u8, imp.sym_name, "args_sizes_get")) {
            e.stack_top -= 2;
            e.push(.{ .u32 = @enumToInt(wasi_args_sizes_get(
                e,
                stack[e.stack_top + 0].u32,
                stack[e.stack_top + 1].u32,
            )) });
        } else if (mem.eql(u8, imp.sym_name, "args_get")) {
            e.stack_top -= 2;
            e.push(.{ .u32 = @enumToInt(wasi_args_get(
                e,
                stack[e.stack_top + 0].u32,
                stack[e.stack_top + 1].u32,
            )) });
        } else if (mem.eql(u8, imp.sym_name, "fd_close")) {
            @panic("TODO implement fd_close");
        } else if (mem.eql(u8, imp.sym_name, "fd_read")) {
            @panic("TODO implement fd_read");
        } else if (mem.eql(u8, imp.sym_name, "fd_filestat_get")) {
            e.stack_top -= 2;
            e.push(.{ .u32 = @enumToInt(wasi_fd_filestat_get(
                e,
                stack[e.stack_top + 0].i32,
                stack[e.stack_top + 1].u32,
            )) });
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
            e.stack_top -= 4;
            e.push(.{ .u32 = @enumToInt(wasi_fd_write(
                e,
                stack[e.stack_top + 0].i32,
                stack[e.stack_top + 1].u32,
                stack[e.stack_top + 2].u32,
                stack[e.stack_top + 3].u32,
            )) });
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

    fn push(e: *Exec, value: Value) void {
        stack[e.stack_top] = value;
        e.stack_top += 1;
    }

    fn pop(e: *Exec) Value {
        e.stack_top -= 1;
        return stack[e.stack_top];
    }

    fn run(e: *Exec) noreturn {
        const module_bytes = e.module_bytes;
        while (true) {
            const frame = &frames[e.frames_index];
            const pc = &frame.pc;
            const op = @intToEnum(wasm.Opcode, module_bytes[pc.*]);
            pc.* += 1;
            //if (e.stack_top > 0) {
            //    log.debug("stack[{d}]={d} pc={d}, op={s}", .{
            //        e.stack_top - 1, stack[e.stack_top - 1].i32, pc.*, @tagName(op),
            //    });
            //} else {
            //    log.debug("<empty> pc={d}, op={s}", .{ pc.*, @tagName(op) });
            //}
            switch (op) {
                .@"unreachable" => @panic("unreachable"),
                .nop => {},
                .block => {
                    const block_type = readVarInt(module_bytes, pc, i32);
                    labels[frame.labels_end] = .{
                        .loop_pc = 0,
                        .block_type = block_type,
                        .stack_top = e.stack_top,
                    };
                    frame.labels_end += 1;
                    //log.debug("set labels_end={d}", .{frame.labels_end});
                },
                .loop => {
                    const block_type = readVarInt(module_bytes, pc, i32);
                    labels[frame.labels_end] = .{
                        .loop_pc = pc.*,
                        .block_type = block_type,
                        .stack_top = e.stack_top,
                    };
                    frame.labels_end += 1;
                    //log.debug("set labels_end={d}", .{frame.labels_end});
                },
                .@"if" => @panic("unhandled opcode: if"),
                .@"else" => @panic("unhandled opcode: else"),
                .end => {
                    const prev_frame = &frames[e.frames_index - 1];
                    //log.debug("labels_end {d}-- (base: {d}) arity={d}", .{
                    //    frame.labels_end, prev_frame.labels_end, frame.return_arity,
                    //});
                    if (frame.labels_end == prev_frame.labels_end) {
                        const n = frame.return_arity;
                        const dst = stack[frame.locals_begin..][0..n];
                        const src = stack[e.stack_top - n ..][0..n];
                        mem.copy(Value, dst, src);
                        e.stack_top = frame.locals_begin + n;
                        e.frames_index -= 1;
                    } else {
                        frame.labels_end -= 1;
                    }
                },
                .br => {
                    const label_idx = readVarInt(module_bytes, pc, u32);
                    e.br(label_idx + 1);
                },
                .br_if => {
                    const label_idx = readVarInt(module_bytes, pc, u32);
                    if (e.pop().u32 != 0) {
                        e.br(label_idx + 1);
                    }
                },
                .br_table => @panic("unhandled opcode: br_table"),
                .@"return" => {
                    const n = frame.return_arity;
                    const dst = stack[frame.locals_begin..][0..n];
                    const src = stack[e.stack_top - n ..][0..n];
                    mem.copy(Value, dst, src);
                    e.stack_top = frame.locals_begin + n;
                    e.frames_index -= 1;
                },
                .call => {
                    const fn_id = readVarInt(module_bytes, pc, u32);
                    e.call(fn_id);
                },
                .call_indirect => {
                    const table_idx = readVarInt(module_bytes, pc, u32);
                    const type_idx = readVarInt(module_bytes, pc, u32);
                    log.debug("table_idx={d} type_idx={d}", .{ table_idx, type_idx });
                    const fn_id = e.pop().u32;
                    e.call(fn_id);
                },
                .drop => {
                    e.stack_top -= 1;
                },
                .select => {
                    const c = stack[e.stack_top - 1].u32;
                    const b = stack[e.stack_top - 2];
                    const a = stack[e.stack_top - 3];
                    stack[e.stack_top - 3] = if (c != 0) a else b;
                    e.stack_top -= 2;
                },
                .local_get => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    //log.debug("reading local at stack[{d}]", .{idx + frame.locals_begin});
                    const val = stack[idx + frame.locals_begin];
                    e.push(val);
                },
                .local_set => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    //log.debug("writing local at stack[{d}]", .{idx + frame.locals_begin});
                    stack[idx + frame.locals_begin] = e.pop();
                },
                .local_tee => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    //log.debug("writing local at stack[{d}]", .{idx + frame.locals_begin});
                    stack[idx + frame.locals_begin] = stack[e.stack_top - 1];
                },
                .global_get => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    e.push(e.globals[idx]);
                },
                .global_set => {
                    const idx = readVarInt(module_bytes, pc, u32);
                    e.globals[idx] = e.pop();
                },
                .i32_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(.{ .i32 = mem.readIntLittle(i32, e.memory[offset..][0..4]) });
                },
                .i64_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(.{ .i64 = mem.readIntLittle(i64, e.memory[offset..][0..8]) });
                },
                .f32_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u32, e.memory[offset..][0..4]);
                    e.push(.{ .f32 = @bitCast(f32, int) });
                },
                .f64_load => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u64, e.memory[offset..][0..8]);
                    e.push(.{ .f64 = @bitCast(f64, int) });
                },
                .i32_load8_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(.{ .i32 = @bitCast(i8, e.memory[offset]) });
                },
                .i32_load8_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const arg = e.pop().u32;
                    const offset = readVarInt(module_bytes, pc, u32);
                    e.push(.{ .u32 = e.memory[offset + arg] });
                },
                .i32_load16_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i16, e.memory[offset..][0..2]);
                    e.push(.{ .i32 = int });
                },
                .i32_load16_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u16, e.memory[offset..][0..2]);
                    e.push(.{ .u32 = int });
                },
                .i64_load8_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(.{ .i64 = @bitCast(i8, e.memory[offset]) });
                },
                .i64_load8_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.push(.{ .u64 = e.memory[offset] });
                },
                .i64_load16_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i16, e.memory[offset..][0..2]);
                    e.push(.{ .i64 = int });
                },
                .i64_load16_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u16, e.memory[offset..][0..2]);
                    e.push(.{ .u64 = int });
                },
                .i64_load32_s => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(i32, e.memory[offset..][0..4]);
                    e.push(.{ .i64 = int });
                },
                .i64_load32_u => {
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    const int = mem.readIntLittle(u32, e.memory[offset..][0..4]);
                    e.push(.{ .u64 = int });
                },
                .i32_store => {
                    const operand = e.pop().i32;
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(i32, e.memory[offset..][0..4], operand);
                },
                .i64_store => {
                    const operand = e.pop().i64;
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(i64, e.memory[offset..][0..8], operand);
                },
                .f32_store => {
                    const int = @bitCast(u32, e.pop().f32);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(u32, e.memory[offset..][0..4], int);
                },
                .f64_store => {
                    const int = @bitCast(u64, e.pop().f64);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(u64, e.memory[offset..][0..8], int);
                },
                .i32_store8 => {
                    const operand = e.pop().u32;
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.memory[offset] = @truncate(u8, operand);
                },
                .i32_store16 => {
                    const small = @truncate(u16, e.pop().u32);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(u16, e.memory[offset..][0..2], small);
                },
                .i64_store8 => {
                    const operand = @truncate(u8, e.pop().u64);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    e.memory[offset] = operand;
                },
                .i64_store16 => {
                    const small = @truncate(u16, e.pop().u64);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(u16, e.memory[offset..][0..2], small);
                },
                .i64_store32 => {
                    const small = @truncate(u32, e.pop().u64);
                    const alignment = readVarInt(module_bytes, pc, u32);
                    _ = alignment;
                    const offset = readVarInt(module_bytes, pc, u32) + e.pop().u32;
                    mem.writeIntLittle(u32, e.memory[offset..][0..4], small);
                },
                .memory_size => {
                    @panic("memory_size");
                },
                .memory_grow => {
                    @panic("memory_grow");
                },
                .i32_const => {
                    const x = readVarInt(module_bytes, pc, i32);
                    e.push(.{ .i32 = x });
                },
                .i64_const => {
                    const x = readVarInt(module_bytes, pc, i64);
                    e.push(.{ .i64 = x });
                },
                .f32_const => {
                    const x = readFloat32(module_bytes, pc);
                    e.push(.{ .f32 = x });
                },
                .f64_const => {
                    const x = readFloat64(module_bytes, pc);
                    e.push(.{ .f64 = x });
                },
                .i32_eqz => {
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 == 0);
                },
                .i32_eq => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 == rhs.i32);
                },
                .i32_ne => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 != rhs.i32);
                },
                .i32_lt_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 < rhs.i32);
                },
                .i32_lt_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = @boolToInt(stack[e.stack_top - 1].u32 < rhs.u32);
                },
                .i32_gt_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 > rhs.i32);
                },
                .i32_gt_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = @boolToInt(stack[e.stack_top - 1].u32 > rhs.u32);
                },
                .i32_le_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 <= rhs.i32);
                },
                .i32_le_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = @boolToInt(stack[e.stack_top - 1].u32 <= rhs.u32);
                },
                .i32_ge_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @boolToInt(stack[e.stack_top - 1].i32 >= rhs.i32);
                },
                .i32_ge_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = @boolToInt(stack[e.stack_top - 1].u32 >= rhs.u32);
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

                .i32_clz => {
                    stack[e.stack_top - 1].u32 = @clz(stack[e.stack_top - 1].u32);
                },
                .i32_ctz => {
                    stack[e.stack_top - 1].u32 = @ctz(stack[e.stack_top - 1].u32);
                },
                .i32_popcnt => {
                    stack[e.stack_top - 1].u32 = @popCount(stack[e.stack_top - 1].u32);
                },
                .i32_add => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 +%= rhs.i32;
                },
                .i32_sub => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 -%= rhs.i32;
                },
                .i32_mul => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 *%= rhs.i32;
                },
                .i32_div_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 *%= rhs.i32;
                },
                .i32_div_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 *%= rhs.u32;
                },
                .i32_rem_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 = @rem(stack[e.stack_top - 1].i32, rhs.i32);
                },
                .i32_rem_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = @rem(stack[e.stack_top - 1].u32, rhs.u32);
                },
                .i32_and => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 &= rhs.u32;
                },
                .i32_or => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 |= rhs.u32;
                },
                .i32_xor => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 ^= rhs.u32;
                },
                .i32_shl => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 <<= @truncate(u5, rhs.u32);
                },
                .i32_shr_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i32 >>= @truncate(u5, rhs.u32);
                },
                .i32_shr_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 >>= @truncate(u5, rhs.u32);
                },
                .i32_rotl => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = std.math.rotl(u32, stack[e.stack_top - 1].u32, rhs.u32);
                },
                .i32_rotr => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u32 = std.math.rotr(u32, stack[e.stack_top - 1].u32, rhs.u32);
                },

                .i64_clz => {
                    stack[e.stack_top - 1].u64 = @clz(stack[e.stack_top - 1].u64);
                },
                .i64_ctz => {
                    stack[e.stack_top - 1].u64 = @ctz(stack[e.stack_top - 1].u64);
                },
                .i64_popcnt => {
                    stack[e.stack_top - 1].u64 = @popCount(stack[e.stack_top - 1].u64);
                },
                .i64_add => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 +%= rhs.i64;
                },
                .i64_sub => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 -%= rhs.i64;
                },
                .i64_mul => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 *%= rhs.i64;
                },
                .i64_div_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 *%= rhs.i64;
                },
                .i64_div_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 *%= rhs.u64;
                },
                .i64_rem_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 = @rem(stack[e.stack_top - 1].i64, rhs.i64);
                },
                .i64_rem_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 = @rem(stack[e.stack_top - 1].u64, rhs.u64);
                },
                .i64_and => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 &= rhs.u64;
                },
                .i64_or => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 |= rhs.u64;
                },
                .i64_xor => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 ^= rhs.u64;
                },
                .i64_shl => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 <<= @truncate(u6, rhs.u64);
                },
                .i64_shr_s => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].i64 >>= @truncate(u6, rhs.u64);
                },
                .i64_shr_u => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 >>= @truncate(u6, rhs.u64);
                },
                .i64_rotl => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 = std.math.rotl(u64, stack[e.stack_top - 1].u64, rhs.u64);
                },
                .i64_rotr => {
                    const rhs = e.pop();
                    stack[e.stack_top - 1].u64 = std.math.rotr(u64, stack[e.stack_top - 1].u64, rhs.u64);
                },

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

const Value = extern union {
    i32: i32,
    u32: u32,
    i64: i64,
    u64: u64,
    f32: f32,
    f64: f64,
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

/// fn args_sizes_get(argc: *usize, argv_buf_size: *usize) errno_t;
fn wasi_args_sizes_get(e: *Exec, argc: u32, argv_buf_size: u32) wasi.errno_t {
    log.debug("wasi_args_sizes_get argc={d} argv_buf_size={d}", .{ argc, argv_buf_size });
    mem.writeIntLittle(u32, e.memory[argc..][0..4], @intCast(u32, e.args.len));
    var buf_size: usize = 0;
    for (e.args) |arg| {
        buf_size += arg.len + 1;
    }
    mem.writeIntLittle(u32, e.memory[argv_buf_size..][0..4], @intCast(u32, buf_size));
    return .SUCCESS;
}

var preopens_buffer: [10]Preopen = undefined;
var preopens_len: usize = 0;

const Preopen = struct {
    wasi_fd: i32,
    name: []const u8,
    host_fd: os.fd_t,
};

fn addPreopen(wasi_fd: i32, name: []const u8, host_fd: os.fd_t) void {
    preopens_buffer[preopens_len] = .{
        .wasi_fd = wasi_fd,
        .name = name,
        .host_fd = host_fd,
    };
    preopens_len += 1;
}

fn findPreopen(wasi_fd: i32) ?Preopen {
    for (preopens_buffer[0..preopens_len]) |preopen| {
        if (preopen.wasi_fd == wasi_fd) {
            return preopen;
        }
    }
    return null;
}

/// fn fd_prestat_get(fd: fd_t, buf: *prestat_t) errno_t;
/// const prestat_t = extern struct {
///     pr_type: u8,
///     u: usize,
/// };
fn wasi_fd_prestat_get(e: *Exec, fd: i32, buf: u32) wasi.errno_t {
    log.debug("wasi_fd_prestat_get fd={d} buf={d}", .{ fd, buf });
    const preopen = findPreopen(fd) orelse return .BADF;
    mem.writeIntLittle(u32, e.memory[buf + 0 ..][0..4], 0);
    mem.writeIntLittle(u32, e.memory[buf + 4 ..][0..4], @intCast(u32, preopen.name.len));
    return .SUCCESS;
}

/// fn fd_prestat_dir_name(fd: fd_t, path: [*]u8, path_len: usize) errno_t;
fn wasi_fd_prestat_dir_name(e: *Exec, fd: i32, path: u32, path_len: u32) wasi.errno_t {
    log.debug("wasi_fd_prestat_dir_name fd={d} path={d} path_len={d}", .{ fd, path, path_len });
    const preopen = findPreopen(fd) orelse return .BADF;
    assert(path_len == preopen.name.len);
    mem.copy(u8, e.memory[path..], preopen.name);
    return .SUCCESS;
}

/// extern fn fd_write(fd: fd_t, iovs: [*]const ciovec_t, iovs_len: usize, nwritten: *usize) errno_t;
/// const ciovec_t = extern struct {
///     base: [*]const u8,
///     len: usize,
/// };
fn wasi_fd_write(e: *Exec, fd: i32, iovs: u32, iovs_len: u32, nwritten: u32) wasi.errno_t {
    log.debug("wasi_fd_write fd={d} iovs={d} iovs_len={d} nwritten={d}", .{
        fd, iovs, iovs_len, nwritten,
    });
    const preopen = findPreopen(fd) orelse return .BADF;
    var i: u32 = 0;
    var total_written: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readIntLittle(u32, e.memory[iovs + i * 8 + 0 ..][0..4]);
        const len = mem.readIntLittle(u32, e.memory[iovs + i * 8 + 4 ..][0..4]);
        const buf = e.memory[ptr..][0..len];
        const written = os.write(preopen.host_fd, buf) catch |err| return toWasiError(err);
        if (written == 0) break;
        total_written += written;
    }
    mem.writeIntLittle(u32, e.memory[nwritten..][0..4], @intCast(u32, total_written));
    return .SUCCESS;
}

/// extern fn fd_filestat_get(fd: fd_t, buf: *filestat_t) errno_t;
/// const filestat_t = extern struct {
///     dev: device_t, u64
///     ino: inode_t, u64
///     filetype: filetype_t, u8
///     nlink: linkcount_t, u64
///     size: filesize_t, u64
///     atim: timestamp_t, u64
///     mtim: timestamp_t, u64
///     ctim: timestamp_t, u64
/// };
fn wasi_fd_filestat_get(e: *Exec, fd: i32, buf: u32) wasi.errno_t {
    log.debug("wasi_fd_filestat_get fd={d} buf={d}", .{ fd, buf });
    const preopen = findPreopen(fd) orelse return .BADF;
    const file = fs.File{ .handle = preopen.host_fd };
    const stat = file.stat() catch |err| return toWasiError(err);
    mem.writeIntLittle(u64, e.memory[buf + 0x00 ..][0..8], 0); // device
    mem.writeIntLittle(u64, e.memory[buf + 0x10 ..][0..8], stat.inode);
    mem.writeIntLittle(u64, e.memory[buf + 0x18 ..][0..8], @enumToInt(toWasiFileType(stat.kind)));
    mem.writeIntLittle(u64, e.memory[buf + 0x20 ..][0..8], 1); // nlink
    mem.writeIntLittle(u64, e.memory[buf + 0x28 ..][0..8], stat.size);
    mem.writeIntLittle(u64, e.memory[buf + 0x30 ..][0..8], toWasiTimestamp(stat.atime));
    mem.writeIntLittle(u64, e.memory[buf + 0x38 ..][0..8], toWasiTimestamp(stat.mtime));
    mem.writeIntLittle(u64, e.memory[buf + 0x40 ..][0..8], toWasiTimestamp(stat.ctime));
    return .SUCCESS;
}

/// extern fn args_get(argv: [*][*:0]u8, argv_buf: [*]u8) errno_t;
fn wasi_args_get(e: *Exec, argv: u32, argv_buf: u32) wasi.errno_t {
    log.debug("wasi_args_get argv={d} argv_buf={d}", .{ argv, argv_buf });
    _ = e;
    @panic("TODO");
}

fn toWasiTimestamp(ns: i128) u64 {
    return @intCast(u64, ns);
}

fn toWasiError(err: anyerror) wasi.errno_t {
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.DiskQuota => .DQUOT,
        error.InputOutput => .IO,
        error.FileTooBig => .FBIG,
        error.NoSpaceLeft => .NOSPC,
        error.BrokenPipe => .PIPE,
        error.NotOpenForWriting => .BADF,
        error.SystemResources => .NOMEM,
        else => std.debug.panic("unexpected error: {s}", .{@errorName(err)}),
    };
}

fn toWasiFileType(kind: fs.File.Kind) wasi.filetype_t {
    return switch (kind) {
        .BlockDevice => .BLOCK_DEVICE,
        .CharacterDevice => .CHARACTER_DEVICE,
        .Directory => .DIRECTORY,
        .SymLink => .SYMBOLIC_LINK,
        .File => .REGULAR_FILE,
        .Unknown => .UNKNOWN,

        .NamedPipe,
        .UnixDomainSocket,
        .Whiteout,
        .Door,
        .EventPort,
        => .UNKNOWN,
    };
}
