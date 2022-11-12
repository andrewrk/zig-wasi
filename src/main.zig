const std = @import("std");
const process = std.process;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const wasm = std.wasm;
const wasi = std.os.wasi;
const os = std.os;
const math = std.math;
const decode_log = std.log.scoped(.decode);
const trace_log = std.log.scoped(.trace);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (scope == .decode) return;
    if (scope == .cpu) return;
    if (scope == .trace) return;
    if (scope == .func) return;
    std.debug.print(format ++ "\n", args);
    _ = level;
}

const max_memory = 3 * 1024 * 1024 * 1024; // 3 GiB

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const memory = try os.mmap(
        null,
        max_memory,
        os.PROT.READ | os.PROT.WRITE,
        os.MAP.PRIVATE | os.MAP.ANONYMOUS,
        -1,
        0,
    );

    const args = try process.argsAlloc(arena);

    const zig_lib_dir_path = args[1];
    const wasm_file = args[2];
    const vm_args = args[2..];

    const max_size = 50 * 1024 * 1024;
    const module_bytes = try fs.cwd().readFileAlloc(arena, wasm_file, max_size);

    const cwd = try fs.cwd().openDir(".", .{});
    const cache_dir = try cwd.makeOpenPath("zig1-cache", .{});
    const zig_lib_dir = try cwd.openDir(zig_lib_dir_path, .{});

    addPreopen(0, "stdin", os.STDIN_FILENO);
    addPreopen(1, "stdout", os.STDOUT_FILENO);
    addPreopen(2, "stderr", os.STDERR_FILENO);
    addPreopen(3, ".", cwd.fd);
    addPreopen(4, "/cache", cache_dir.fd);
    addPreopen(5, "/lib", zig_lib_dir.fd);

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
            imp.mod_name = readName(module_bytes, &i);
            imp.sym_name = readName(module_bytes, &i);
            const desc = readVarInt(module_bytes, &i, wasm.ExternalKind);
            switch (desc) {
                .function => {
                    imp.type_idx = readVarInt(module_bytes, &i, u32);
                },
                .table => unreachable,
                .memory => unreachable,
                .global => unreachable,
            }
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
        var func_i: u32 = section_starts[@enumToInt(wasm.Section.function)];
        const funcs_len = readVarInt(module_bytes, &func_i, u32);
        const functions = try arena.alloc(Function, funcs_len);
        for (functions) |*func| func.type_idx = readVarInt(module_bytes, &func_i, u32);
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
        const globals = try arena.alloc(u64, globals_len);
        for (globals) |*global| {
            const content_type = readVarInt(module_bytes, &i, wasm.Valtype);
            const mutability = readVarInt(module_bytes, &i, Mutability);
            assert(mutability == .@"var");
            assert(content_type == .i32);
            const opcode = @intToEnum(wasm.Opcode, module_bytes[i]);
            i += 1;
            assert(opcode == .i32_const);
            const init = readVarInt(module_bytes, &i, i32);
            global.* = @bitCast(u32, init);
        }
        break :g globals;
    };

    // Allocate and initialize memory.
    const memory_len = m: {
        i = section_starts[@enumToInt(wasm.Section.memory)];
        const memories_len = readVarInt(module_bytes, &i, u32);
        if (memories_len != 1) return error.UnexpectedMemoryCount;
        const flags = readVarInt(module_bytes, &i, u32);
        _ = flags;
        const initial = readVarInt(module_bytes, &i, u32) * wasm.page_size;

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

        break :m initial;
    };

    const table = t: {
        i = section_starts[@enumToInt(wasm.Section.table)];
        const table_count = readVarInt(module_bytes, &i, u32);
        if (table_count == 0) break :t &[0]u32{};
        if (table_count != 1) return error.ExpectedOneTableSection;
        const element_type = readVarInt(module_bytes, &i, u32);
        const has_max = readVarInt(module_bytes, &i, u32);
        assert(has_max == 1);
        const initial = readVarInt(module_bytes, &i, u32);
        const maximum = readVarInt(module_bytes, &i, u32);
        cpu_log.debug("table element_type={x} initial={d} maximum={d}", .{
            element_type, initial, maximum,
        });

        i = section_starts[@enumToInt(wasm.Section.element)];
        const element_section_count = readVarInt(module_bytes, &i, u32);
        if (element_section_count != 1) return error.ExpectedOneElementSection;
        const flags = readVarInt(module_bytes, &i, u32);
        cpu_log.debug("flags={x}", .{flags});
        const opcode = @intToEnum(wasm.Opcode, module_bytes[i]);
        i += 1;
        assert(opcode == .i32_const);
        const offset = readVarInt(module_bytes, &i, u32);
        const end = @intToEnum(wasm.Opcode, module_bytes[i]);
        assert(end == .end);
        i += 1;
        const elem_count = readVarInt(module_bytes, &i, u32);

        cpu_log.debug("elem offset={d} count={d}", .{ offset, elem_count });

        const table = try arena.alloc(u32, maximum);
        mem.set(u32, table, 0);

        var elem_i: u32 = 0;
        while (elem_i < elem_count) : (elem_i += 1) {
            table[elem_i + offset] = readVarInt(module_bytes, &i, u32);
        }
        break :t table;
    };

    frames[0] = .{
        .fn_idx = 0,
        .opcode_pc = undefined,
        .operand_pc = undefined,
        .stack_begin = undefined,
        .locals_begin = undefined,
        .return_arity = 0,
    };

    var vm: VirtualMachine = .{
        .stack = try arena.alloc(u64, 10000000),
        .module_bytes = module_bytes,
        .opcodes = try arena.alloc(u8, 5000000),
        .operands = try arena.alloc(u32, 5000000),
        .stack_top = 0,
        .frames_index = 1,
        .functions = functions,
        .types = types,
        .globals = globals,
        .memory = memory,
        .memory_len = memory_len,
        .imports = imports,
        .args = vm_args,
        .table = table,
    };

    {
        var code_i: u32 = section_starts[@enumToInt(wasm.Section.code)];
        const codes_len = readVarInt(module_bytes, &code_i, u32);
        assert(codes_len == functions.len);
        var opcode_pc: u32 = 0;
        var operand_pc: u32 = 0;
        for (functions) |*func| {
            const size = readVarInt(module_bytes, &code_i, u32);
            const code_begin = code_i;

            func.locals_count = 0;
            var local_sets_count = readVarInt(module_bytes, &code_i, u32);
            while (local_sets_count > 0) : (local_sets_count -= 1) {
                const current_count = readVarInt(module_bytes, &code_i, u32);
                const local_type = readVarInt(module_bytes, &code_i, u32);
                _ = local_type;
                func.locals_count += current_count;
            }

            func.opcode_pc = opcode_pc;
            func.operand_pc = operand_pc;
            vm.decodeCode(func, &code_i, &opcode_pc, &operand_pc);
            assert(code_i == code_begin + size);
        }
    }

    vm.call(start_fn_idx);
    vm.run();
}

const section_count = @typeInfo(wasm.Section).Enum.fields.len;
var frames: [100000]Frame = undefined;
var blocks: [100000]Block = undefined;

const Frame = struct {
    fn_idx: u32,
    /// Index to start of code in opcodes/operands.
    opcode_pc: u32,
    operand_pc: u32,
    stack_begin: u32,
    locals_begin: u32,
    return_arity: u32,
};

const Mutability = enum { @"const", @"var" };

const Function = struct {
    /// Index to start of code in opcodes/operands.
    opcode_pc: u32,
    operand_pc: u32,
    locals_count: u32,
    /// Index into types.
    type_idx: u32,
};

const Import = struct {
    sym_name: []const u8,
    mod_name: []const u8,
    /// Index into types.
    type_idx: u32,
};

/// This is currently in units of number of u64 stack entries
fn typeSize(ty: i32) u1 {
    return if (ty >= 0)
        unreachable
    else if (ty == -0x40)
        0
    else
        1;
}

fn funcTypeInfo(module_bytes: []const u8, ty_i: u32) struct { param_count: u32, return_arity: u32 } {
    var i: u32 = ty_i;
    assert(readVarInt(module_bytes, &i, i32) == -0x20);
    const param_count = readVarInt(module_bytes, &i, u32);
    i += param_count;
    const return_arity = readVarInt(module_bytes, &i, u32);
    i += return_arity;
    return .{ .param_count = param_count, .return_arity = return_arity };
}

const Block = struct {
    stack_depth: u32,
    block_type: i32,
    loop_opcode_pc_or_max: u32,
    loop_operand_pc_or_fixups: u32,
};

const VirtualMachine = struct {
    stack: []u64,
    /// Points to one after the last stack item.
    stack_top: u32,
    frames_index: u32,
    memory_len: u32,
    module_bytes: []const u8,
    opcodes: []u8,
    operands: []u32,
    functions: []const Function,
    /// Type index to start of type in module_bytes.
    types: []const u32,
    globals: []u64,
    memory: []u8,
    imports: []const Import,
    args: []const []const u8,
    table: []const u32,

    fn decodeCode(vm: *VirtualMachine, func: *Function, code_i: *u32, opcode_pc: *u32, operand_pc: *u32) void {
        const module_bytes = vm.module_bytes;
        const opcodes = vm.opcodes;
        const operands = vm.operands;
        var stack_depth: u32 = 0;
        var blocks_i: u32 = 0;
        while (true) {
            const opcode = module_bytes[code_i.*];
            code_i.* += 1;

            decode_log.debug("stack_depth = {}, opcode = {s}", .{
                stack_depth,
                @tagName(@intToEnum(wasm.Opcode, opcode)),
            });

            var prefixed_opcode: u8 = undefined;
            stack_depth = switch (@intToEnum(wasm.Opcode, opcode)) {
                .@"unreachable",
                .nop,
                .block,
                .loop,
                .@"else",
                .end,
                .br,
                .call,
                => stack_depth,

                .@"return" => stack_depth - funcTypeInfo(module_bytes, vm.types[func.type_idx]).return_arity,

                .@"if",
                .br_if,
                .br_table,
                .call_indirect,
                .drop,
                .local_set,
                .global_set,
                => stack_depth - 1,

                .select => stack_depth - 3 + 1,
                .local_get,
                .global_get,
                .memory_size,
                .i32_const,
                .i64_const,
                .f32_const,
                .f64_const,
                => stack_depth + 1,

                .local_tee,
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
                .memory_grow,
                .i32_eqz,
                .i32_clz,
                .i32_ctz,
                .i32_popcnt,
                .i64_eqz,
                .i64_clz,
                .i64_ctz,
                .i64_popcnt,
                .f32_abs,
                .f32_neg,
                .f32_ceil,
                .f32_floor,
                .f32_trunc,
                .f32_nearest,
                .f32_sqrt,
                .f64_abs,
                .f64_neg,
                .f64_ceil,
                .f64_floor,
                .f64_trunc,
                .f64_nearest,
                .f64_sqrt,
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
                => stack_depth - 1 + 1,

                .i32_store,
                .i64_store,
                .f32_store,
                .f64_store,
                .i32_store8,
                .i32_store16,
                .i64_store8,
                .i64_store16,
                .i64_store32,
                => stack_depth - 2,

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
                .f32_add,
                .f32_sub,
                .f32_mul,
                .f32_div,
                .f32_min,
                .f32_max,
                .f32_copysign,
                .f64_add,
                .f64_sub,
                .f64_mul,
                .f64_div,
                .f64_min,
                .f64_max,
                .f64_copysign,
                => stack_depth - 2 + 1,

                .prefixed => prefixed: {
                    prefixed_opcode = @intCast(u8, readVarInt(module_bytes, code_i, u32));
                    break :prefixed switch (@intToEnum(wasm.PrefixedOpcode, prefixed_opcode)) {
                        .i32_trunc_sat_f32_s,
                        .i32_trunc_sat_f32_u,
                        .i32_trunc_sat_f64_s,
                        .i32_trunc_sat_f64_u,
                        .i64_trunc_sat_f32_s,
                        .i64_trunc_sat_f32_u,
                        .i64_trunc_sat_f64_s,
                        .i64_trunc_sat_f64_u,
                        => stack_depth - 1 + 1,

                        .memory_init,
                        .memory_copy,
                        .memory_fill,
                        .table_init,
                        .table_copy,
                        .table_fill,
                        => stack_depth - 3,

                        .data_drop,
                        .elem_drop,
                        => stack_depth,

                        .table_grow => stack_depth - 2 + 1,

                        .table_size => stack_depth + 1,

                        _ => unreachable,
                    };
                },

                _ => unreachable,
            };

            switch (@intToEnum(wasm.Opcode, opcode)) {
                .block => {
                    const block_type = readVarInt(module_bytes, code_i, i32);
                    blocks[blocks_i] = .{
                        .stack_depth = stack_depth,
                        .block_type = block_type,
                        .loop_opcode_pc_or_max = std.math.maxInt(u32),
                        .loop_operand_pc_or_fixups = std.math.maxInt(u32),
                    };
                    blocks_i += 1;
                },
                .loop => {
                    const block_type = readVarInt(module_bytes, code_i, i32);
                    blocks[blocks_i] = .{
                        .stack_depth = stack_depth,
                        .block_type = block_type,
                        .loop_opcode_pc_or_max = opcode_pc.*,
                        .loop_operand_pc_or_fixups = operand_pc.*,
                    };
                    blocks_i += 1;
                },
                .@"if" => @panic("unhandled opcode: if"),
                .@"else" => @panic("unhandled opcode: else"),
                .end => {
                    if (blocks_i == 0) {
                        opcodes[opcode_pc.*] = @enumToInt(wasm.Opcode.@"return");
                        opcode_pc.* += 1;
                        return;
                    }
                    blocks_i -= 1;
                    const block = &blocks[blocks_i];
                    if (block.loop_opcode_pc_or_max == std.math.maxInt(u32)) {
                        var next_fixup = block.loop_operand_pc_or_fixups;
                        while (next_fixup != std.math.maxInt(u32)) {
                            const fixup_operand_i = next_fixup;
                            next_fixup = operands[fixup_operand_i];
                            operands[fixup_operand_i] = opcode_pc.*;
                            operands[fixup_operand_i + 1] = operand_pc.*;
                        }
                    }
                    assert(stack_depth > std.math.maxInt(u32) / 4 or stack_depth == block.stack_depth);
                    stack_depth = block.stack_depth + typeSize(block.block_type);
                },
                .br, .br_if => {
                    const label_idx = readVarInt(module_bytes, code_i, u32);
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    const target_block = &blocks[blocks_i - 1 - label_idx];
                    const is_loop = target_block.loop_opcode_pc_or_max != std.math.maxInt(u32);
                    if (!is_loop) stack_depth -= typeSize(target_block.block_type);
                    operands[operand_pc.*] = (stack_depth - target_block.stack_depth) << 1 |
                        typeSize(target_block.block_type);
                    if (is_loop) {
                        operands[operand_pc.* + 1] = target_block.loop_opcode_pc_or_max;
                        operands[operand_pc.* + 2] = target_block.loop_operand_pc_or_fixups;
                    } else {
                        operands[operand_pc.* + 1] = target_block.loop_operand_pc_or_fixups;
                        target_block.loop_operand_pc_or_fixups = operand_pc.* + 1;
                    }
                    operand_pc.* += 3;
                },
                .br_table => {
                    const labels_len = readVarInt(module_bytes, code_i, u32);
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = labels_len;
                    operand_pc.* += 1;
                    var i: u32 = 0;
                    var common_block_type: i32 = undefined;
                    while (i <= labels_len) : (i += 1) {
                        const label_idx = readVarInt(module_bytes, code_i, u32);
                        const target_block = &blocks[blocks_i - 1 - label_idx];
                        const is_loop = target_block.loop_opcode_pc_or_max != std.math.maxInt(u32);
                        const block_type = if (is_loop) -0x40 else target_block.block_type;
                        if (i == 0) {
                            stack_depth -= typeSize(block_type);
                            common_block_type = block_type;
                        } else assert(block_type == common_block_type);
                        operands[operand_pc.*] = (stack_depth - target_block.stack_depth) << 1 |
                            typeSize(block_type);
                        if (is_loop) {
                            operands[operand_pc.* + 1] = target_block.loop_opcode_pc_or_max;
                            operands[operand_pc.* + 2] = target_block.loop_operand_pc_or_fixups;
                        } else {
                            operands[operand_pc.* + 1] = target_block.loop_operand_pc_or_fixups;
                            target_block.loop_operand_pc_or_fixups = operand_pc.* + 1;
                        }
                        operand_pc.* += 3;
                    }
                },
                .call => {
                    const fn_id = readVarInt(module_bytes, code_i, u32);
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = fn_id;
                    operand_pc.* += 1;
                    const type_idx = if (fn_id < vm.imports.len)
                        vm.imports[fn_id].type_idx
                    else
                        vm.functions[fn_id - @intCast(u32, vm.imports.len)].type_idx;
                    const info = funcTypeInfo(module_bytes, vm.types[type_idx]);
                    stack_depth = stack_depth - info.param_count + info.return_arity;
                },
                .call_indirect => {
                    const type_idx = readVarInt(module_bytes, code_i, u32);
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = type_idx;
                    operand_pc.* += 1;
                    assert(readVarInt(module_bytes, code_i, u32) == 0);
                    const info = funcTypeInfo(module_bytes, vm.types[type_idx]);
                    stack_depth = stack_depth - info.param_count + info.return_arity;
                },
                .local_get,
                .local_set,
                .local_tee,
                .global_get,
                .global_set,
                => {
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = readVarInt(module_bytes, code_i, u32);
                    operand_pc.* += 1;
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
                => {
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    _ = readVarInt(module_bytes, code_i, u32);
                    operands[operand_pc.*] = readVarInt(module_bytes, code_i, u32);
                    operand_pc.* += 1;
                },
                .memory_size, .memory_grow => {
                    assert(module_bytes[code_i.*] == 0);
                    code_i.* += 1;
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                },
                .i32_const => {
                    const x = @bitCast(u32, readVarInt(module_bytes, code_i, i32));
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = x;
                    operand_pc.* += 1;
                },
                .i64_const => {
                    const x = @bitCast(u64, readVarInt(module_bytes, code_i, i64));
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = @truncate(u32, x);
                    operands[operand_pc.* + 1] = @truncate(u32, x >> 32);
                    operand_pc.* += 2;
                },
                .f32_const => {
                    const x = @bitCast(u32, readFloat32(module_bytes, code_i));
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = x;
                    operand_pc.* += 1;
                },
                .f64_const => {
                    const x = @bitCast(u64, readFloat64(module_bytes, code_i));
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                    operands[operand_pc.*] = @truncate(u32, x);
                    operands[operand_pc.* + 1] = @truncate(u32, x >> 32);
                    operand_pc.* += 2;
                },
                .prefixed => switch (@intToEnum(wasm.PrefixedOpcode, prefixed_opcode)) {
                    .i32_trunc_sat_f32_s,
                    .i32_trunc_sat_f32_u,
                    .i32_trunc_sat_f64_s,
                    .i32_trunc_sat_f64_u,
                    .i64_trunc_sat_f32_s,
                    .i64_trunc_sat_f32_u,
                    .i64_trunc_sat_f64_s,
                    .i64_trunc_sat_f64_u,
                    => {
                        opcodes[opcode_pc.*] = opcode;
                        opcodes[opcode_pc.* + 1] = prefixed_opcode;
                        opcode_pc.* += 2;
                    },
                    .memory_copy => {
                        assert(module_bytes[code_i.*] == 0 and module_bytes[code_i.* + 1] == 0);
                        code_i.* += 2;
                        opcodes[opcode_pc.*] = opcode;
                        opcodes[opcode_pc.* + 1] = prefixed_opcode;
                        opcode_pc.* += 2;
                    },
                    .memory_fill => {
                        assert(module_bytes[code_i.*] == 0);
                        code_i.* += 1;
                        opcodes[opcode_pc.*] = opcode;
                        opcodes[opcode_pc.* + 1] = prefixed_opcode;
                        opcode_pc.* += 2;
                    },
                    else => unreachable,
                },
                else => {
                    opcodes[opcode_pc.*] = opcode;
                    opcode_pc.* += 1;
                },
            }

            switch (@intToEnum(wasm.Opcode, opcode)) {
                .@"unreachable",
                .@"return",
                .br,
                .br_table,
                => stack_depth = std.math.maxInt(u32) / 2,

                else => {},
            }
        }
    }

    fn br(vm: *VirtualMachine) void {
        const frame = &frames[vm.frames_index];
        const stack_info = vm.operands[frame.operand_pc];
        const result_size = @truncate(u1, stack_info);
        const stack_adjust = stack_info >> 1;
        std.mem.copy(
            u64,
            vm.stack[vm.stack_top - stack_adjust ..],
            vm.stack[vm.stack_top..][0..result_size],
        );
        vm.stack_top -= stack_adjust;
        frame.opcode_pc = vm.operands[frame.operand_pc + 1];
        frame.operand_pc = vm.operands[frame.operand_pc + 2];
    }

    fn call(vm: *VirtualMachine, fn_id: u32) void {
        if (fn_id < vm.imports.len) {
            const imp = vm.imports[fn_id];
            return callImport(vm, imp);
        }
        const fn_idx = fn_id - @intCast(u32, vm.imports.len);
        const module_bytes = vm.module_bytes;
        const func = vm.functions[fn_idx];
        const info = funcTypeInfo(module_bytes, vm.types[func.type_idx]);
        const locals_begin = vm.stack_top - info.param_count;

        func_log.debug("fn_idx: {d}, type_idx: {d}, param_count: {d}, return_arity: {d}, locals_begin: {d}, locals_count: {d}", .{
            fn_idx, func.type_idx, info.param_count, info.return_arity, locals_begin, func.locals_count,
        });

        // Push zeroed locals to stack
        mem.set(u64, vm.stack[vm.stack_top..][0..func.locals_count], 0);
        vm.stack_top += func.locals_count;

        vm.frames_index += 1;
        frames[vm.frames_index] = .{
            .fn_idx = fn_idx,
            .return_arity = info.return_arity,
            .opcode_pc = func.opcode_pc,
            .operand_pc = func.operand_pc,
            .stack_begin = vm.stack_top,
            .locals_begin = locals_begin,
        };
    }

    fn callImport(vm: *VirtualMachine, imp: Import) void {
        if (mem.eql(u8, imp.sym_name, "fd_prestat_get")) {
            const buf = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_prestat_get(vm, fd, buf)));
        } else if (mem.eql(u8, imp.sym_name, "fd_prestat_dir_name")) {
            const path_len = vm.pop(u32);
            const path = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_prestat_dir_name(vm, fd, path, path_len)));
        } else if (mem.eql(u8, imp.sym_name, "fd_close")) {
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_close(vm, fd)));
        } else if (mem.eql(u8, imp.sym_name, "fd_read")) {
            const nread = vm.pop(u32);
            const iovs_len = vm.pop(u32);
            const iovs = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_read(vm, fd, iovs, iovs_len, nread)));
        } else if (mem.eql(u8, imp.sym_name, "fd_filestat_get")) {
            const buf = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_filestat_get(vm, fd, buf)));
        } else if (mem.eql(u8, imp.sym_name, "fd_filestat_set_size")) {
            const size = vm.pop(u64);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_filestat_set_size(vm, fd, size)));
        } else if (mem.eql(u8, imp.sym_name, "fd_filestat_set_times")) {
            @panic("TODO implement fd_filestat_set_times");
        } else if (mem.eql(u8, imp.sym_name, "fd_fdstat_get")) {
            const buf = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_fdstat_get(vm, fd, buf)));
        } else if (mem.eql(u8, imp.sym_name, "fd_readdir")) {
            @panic("TODO implement fd_readdir");
        } else if (mem.eql(u8, imp.sym_name, "fd_write")) {
            const nwritten = vm.pop(u32);
            const iovs_len = vm.pop(u32);
            const iovs = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_write(vm, fd, iovs, iovs_len, nwritten)));
        } else if (mem.eql(u8, imp.sym_name, "fd_pwrite")) {
            const nwritten = vm.pop(u32);
            const offset = vm.pop(u64);
            const iovs_len = vm.pop(u32);
            const iovs = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_fd_pwrite(vm, fd, iovs, iovs_len, offset, nwritten)));
        } else if (mem.eql(u8, imp.sym_name, "proc_exit")) {
            std.process.exit(@intCast(u8, vm.pop(u32)));
            unreachable;
        } else if (mem.eql(u8, imp.sym_name, "args_sizes_get")) {
            const argv_buf_size = vm.pop(u32);
            const argc = vm.pop(u32);
            vm.push(u64, @enumToInt(wasi_args_sizes_get(vm, argc, argv_buf_size)));
        } else if (mem.eql(u8, imp.sym_name, "args_get")) {
            const argv_buf = vm.pop(u32);
            const argv = vm.pop(u32);
            vm.push(u64, @enumToInt(wasi_args_get(vm, argv, argv_buf)));
        } else if (mem.eql(u8, imp.sym_name, "random_get")) {
            const buf_len = vm.pop(u32);
            const buf = vm.pop(u32);
            vm.push(u64, @enumToInt(wasi_random_get(vm, buf, buf_len)));
        } else if (mem.eql(u8, imp.sym_name, "environ_sizes_get")) {
            @panic("TODO implement environ_sizes_get");
        } else if (mem.eql(u8, imp.sym_name, "environ_get")) {
            @panic("TODO implement environ_get");
        } else if (mem.eql(u8, imp.sym_name, "path_filestat_get")) {
            const buf = vm.pop(u32);
            const path_len = vm.pop(u32);
            const path = vm.pop(u32);
            const flags = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_path_filestat_get(vm, fd, flags, path, path_len, buf)));
        } else if (mem.eql(u8, imp.sym_name, "path_create_directory")) {
            const path_len = vm.pop(u32);
            const path = vm.pop(u32);
            const fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_path_create_directory(vm, fd, path, path_len)));
        } else if (mem.eql(u8, imp.sym_name, "path_rename")) {
            const new_path_len = vm.pop(u32);
            const new_path = vm.pop(u32);
            const new_fd = vm.pop(i32);
            const old_path_len = vm.pop(u32);
            const old_path = vm.pop(u32);
            const old_fd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_path_rename(
                vm,
                old_fd,
                old_path,
                old_path_len,
                new_fd,
                new_path,
                new_path_len,
            )));
        } else if (mem.eql(u8, imp.sym_name, "path_open")) {
            const fd = vm.pop(u32);
            const fs_flags = vm.pop(u32);
            const fs_rights_inheriting = vm.pop(u64);
            const fs_rights_base = vm.pop(u64);
            const oflags = vm.pop(u32);
            const path_len = vm.pop(u32);
            const path = vm.pop(u32);
            const dirflags = vm.pop(u32);
            const dirfd = vm.pop(i32);
            vm.push(u64, @enumToInt(wasi_path_open(
                vm,
                dirfd,
                dirflags,
                path,
                path_len,
                @intCast(u16, oflags),
                fs_rights_base,
                fs_rights_inheriting,
                @intCast(u16, fs_flags),
                fd,
            )));
        } else if (mem.eql(u8, imp.sym_name, "path_remove_directory")) {
            @panic("TODO implement path_remove_directory");
        } else if (mem.eql(u8, imp.sym_name, "path_unlink_file")) {
            @panic("TODO implement path_unlink_file");
        } else if (mem.eql(u8, imp.sym_name, "clock_time_get")) {
            const timestamp = vm.pop(u32);
            const precision = vm.pop(u64);
            const clock_id = vm.pop(u32);
            vm.push(u64, @enumToInt(wasi_clock_time_get(vm, clock_id, precision, timestamp)));
        } else if (mem.eql(u8, imp.sym_name, "fd_pread")) {
            @panic("TODO implement fd_pread");
        } else if (mem.eql(u8, imp.sym_name, "debug")) {
            const number = vm.pop(u64);
            const text = vm.pop(u32);
            wasi_debug(vm, text, number);
        } else if (mem.eql(u8, imp.sym_name, "debug_slice")) {
            const len = vm.pop(u32);
            const ptr = vm.pop(u32);
            wasi_debug_slice(vm, ptr, len);
        } else {
            std.debug.panic("unhandled import: {s}", .{imp.sym_name});
        }
    }

    fn push(vm: *VirtualMachine, comptime T: type, value: T) void {
        vm.stack[vm.stack_top] = switch (T) {
            i32 => @bitCast(u32, value),
            i64 => @bitCast(u64, value),
            f32 => @bitCast(u32, value),
            f64 => @bitCast(u64, value),
            u32 => value,
            u64 => value,
            else => @compileError("bad push type"),
        };
        vm.stack_top += 1;
    }

    fn pop(vm: *VirtualMachine, comptime T: type) T {
        vm.stack_top -= 1;
        const value = vm.stack[vm.stack_top];
        return switch (T) {
            i32 => @bitCast(i32, @truncate(u32, value)),
            i64 => @bitCast(i64, value),
            f32 => @bitCast(f32, @truncate(u32, value)),
            f64 => @bitCast(f64, value),
            u32 => @truncate(u32, value),
            u64 => value,
            else => @compileError("bad pop type"),
        };
    }

    fn run(vm: *VirtualMachine) noreturn {
        const opcodes = vm.opcodes;
        const operands = vm.operands;
        while (true) {
            const frame = &frames[vm.frames_index];
            const opcode_pc = &frame.opcode_pc;
            const operand_pc = &frame.operand_pc;
            const op = @intToEnum(wasm.Opcode, opcodes[opcode_pc.*]);
            opcode_pc.* += 1;
            if (vm.stack_top > 0) {
                cpu_log.debug("stack[{d}]={x} pc={d}:{d}, op={s}", .{
                    vm.stack_top - 1, vm.stack[vm.stack_top - 1], opcode_pc.*, operand_pc.*, @tagName(op),
                });
            } else {
                cpu_log.debug("<empty> pc={d}:{d}, op={s}", .{ opcode_pc.*, operand_pc.*, @tagName(op) });
            }
            switch (op) {
                .@"unreachable" => @panic("unreachable reached"),
                .nop => {},
                .block,
                .loop,
                .@"if",
                .@"else",
                .end,
                => @panic("not produced by decodeCode"),
                .br => {
                    vm.br();
                },
                .br_if => {
                    if (vm.pop(u32) != 0) {
                        vm.br();
                    } else {
                        operand_pc.* += 3;
                    }
                },
                .br_table => {
                    const index = @min(vm.pop(u32), operands[operand_pc.*]);
                    operand_pc.* += 1 + index * 3;
                    vm.br();
                },
                .@"return" => {
                    const n = frame.return_arity;
                    const dst = vm.stack[frame.locals_begin..][0..n];
                    const src = vm.stack[vm.stack_top - n ..][0..n];
                    mem.copy(u64, dst, src);
                    vm.stack_top = frame.locals_begin + n;
                    vm.frames_index -= 1;
                },
                .call => {
                    const fn_id = operands[operand_pc.*];
                    operand_pc.* += 1;
                    vm.call(fn_id);
                },
                .call_indirect => {
                    const type_idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    cpu_log.debug("type_idx={d}", .{type_idx});
                    const fn_id = vm.table[vm.pop(u32)];
                    vm.call(fn_id);
                },
                .drop => {
                    vm.stack_top -= 1;
                },
                .select => {
                    const c = vm.pop(u32);
                    const b = vm.pop(u64);
                    const a = vm.pop(u64);
                    const result = if (c != 0) a else b;
                    vm.push(u64, result);
                },
                .local_get => {
                    const idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    //cpu_log.debug("reading local at stack[{d}]", .{idx + frame.locals_begin});
                    const val = vm.stack[idx + frame.locals_begin];
                    vm.push(u64, val);
                },
                .local_set => {
                    const idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    //cpu_log.debug("writing local at stack[{d}]", .{idx + frame.locals_begin});
                    vm.stack[idx + frame.locals_begin] = vm.pop(u64);
                },
                .local_tee => {
                    const idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    //cpu_log.debug("writing local at stack[{d}]", .{idx + frame.locals_begin});
                    vm.stack[idx + frame.locals_begin] = vm.stack[vm.stack_top - 1];
                },
                .global_get => {
                    const idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    vm.push(u64, vm.globals[idx]);
                },
                .global_set => {
                    const idx = operands[operand_pc.*];
                    operand_pc.* += 1;
                    vm.globals[idx] = vm.pop(u64);
                },
                .i32_load => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(u32, mem.readIntLittle(u32, vm.memory[offset..][0..4]));
                },
                .i64_load => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(u64, mem.readIntLittle(u64, vm.memory[offset..][0..8]));
                },
                .f32_load => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(u32, vm.memory[offset..][0..4]);
                    vm.push(u32, int);
                },
                .f64_load => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(u64, vm.memory[offset..][0..8]);
                    vm.push(u64, int);
                },
                .i32_load8_s => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(i32, @bitCast(i8, vm.memory[offset]));
                },
                .i32_load8_u => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(u32, vm.memory[offset]);
                },
                .i32_load16_s => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(i16, vm.memory[offset..][0..2]);
                    vm.push(i32, int);
                },
                .i32_load16_u => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(u16, vm.memory[offset..][0..2]);
                    vm.push(u32, int);
                },
                .i64_load8_s => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(i64, @bitCast(i8, vm.memory[offset]));
                },
                .i64_load8_u => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.push(u64, vm.memory[offset]);
                },
                .i64_load16_s => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(i16, vm.memory[offset..][0..2]);
                    vm.push(i64, int);
                },
                .i64_load16_u => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(u16, vm.memory[offset..][0..2]);
                    vm.push(u64, int);
                },
                .i64_load32_s => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(i32, vm.memory[offset..][0..4]);
                    vm.push(i64, int);
                },
                .i64_load32_u => {
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    const int = mem.readIntLittle(u32, vm.memory[offset..][0..4]);
                    vm.push(u64, int);
                },
                .i32_store => {
                    const operand = vm.pop(u32);
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u32, vm.memory[offset..][0..4], operand);
                },
                .i64_store => {
                    const operand = vm.pop(u64);
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u64, vm.memory[offset..][0..8], operand);
                },
                .f32_store => {
                    const int = @bitCast(u32, vm.pop(f32));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u32, vm.memory[offset..][0..4], int);
                },
                .f64_store => {
                    const int = @bitCast(u64, vm.pop(f64));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u64, vm.memory[offset..][0..8], int);
                },
                .i32_store8 => {
                    const small = @truncate(u8, vm.pop(u32));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.memory[offset] = small;
                },
                .i32_store16 => {
                    const small = @truncate(u16, vm.pop(u32));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u16, vm.memory[offset..][0..2], small);
                },
                .i64_store8 => {
                    const operand = @truncate(u8, vm.pop(u64));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    vm.memory[offset] = operand;
                },
                .i64_store16 => {
                    const small = @truncate(u16, vm.pop(u64));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u16, vm.memory[offset..][0..2], small);
                },
                .i64_store32 => {
                    const small = @truncate(u32, vm.pop(u64));
                    const offset = operands[operand_pc.*] + vm.pop(u32);
                    operand_pc.* += 1;
                    mem.writeIntLittle(u32, vm.memory[offset..][0..4], small);
                },
                .memory_size => {
                    const page_count = @intCast(u32, vm.memory_len / wasm.page_size);
                    vm.push(u32, page_count);
                },
                .memory_grow => {
                    const page_count = vm.pop(u32);
                    const old_page_count = @intCast(u32, vm.memory_len / wasm.page_size);
                    const new_len = vm.memory_len + page_count * wasm.page_size;
                    if (new_len > vm.memory.len) {
                        vm.push(i32, -1);
                    } else {
                        vm.memory_len = new_len;
                        vm.push(u32, old_page_count);
                    }
                },
                .i32_const => {
                    const x = operands[operand_pc.*];
                    operand_pc.* += 1;
                    vm.push(i32, @bitCast(i32, x));
                },
                .i64_const => {
                    const x = operands[operand_pc.*] | @as(u64, operands[operand_pc.* + 1]) << 32;
                    operand_pc.* += 2;
                    vm.push(i64, @bitCast(i64, x));
                },
                .f32_const => {
                    const x = operands[operand_pc.*];
                    operand_pc.* += 1;
                    vm.push(f32, @bitCast(f32, x));
                },
                .f64_const => {
                    const x = operands[operand_pc.*] | @as(u64, operands[operand_pc.* + 1]) << 32;
                    operand_pc.* += 2;
                    vm.push(f64, @bitCast(f64, x));
                },
                .i32_eqz => {
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs == 0));
                },
                .i32_eq => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs == rhs));
                },
                .i32_ne => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs != rhs));
                },
                .i32_lt_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u64, @boolToInt(lhs < rhs));
                },
                .i32_lt_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs < rhs));
                },
                .i32_gt_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .i32_gt_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .i32_le_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .i32_le_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .i32_ge_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },
                .i32_ge_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },
                .i64_eqz => {
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs == 0));
                },
                .i64_eq => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs == rhs));
                },
                .i64_ne => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs != rhs));
                },
                .i64_lt_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u64, @boolToInt(lhs < rhs));
                },
                .i64_lt_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs < rhs));
                },
                .i64_gt_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .i64_gt_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .i64_le_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .i64_le_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .i64_ge_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },
                .i64_ge_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },
                .f32_eq => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs == rhs));
                },
                .f32_ne => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs != rhs));
                },
                .f32_lt => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs < rhs));
                },
                .f32_gt => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .f32_le => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .f32_ge => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },
                .f64_eq => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs == rhs));
                },
                .f64_ne => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs != rhs));
                },
                .f64_lt => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .f64_gt => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs > rhs));
                },
                .f64_le => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs <= rhs));
                },
                .f64_ge => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(u64, @boolToInt(lhs >= rhs));
                },

                .i32_clz => {
                    const operand = vm.pop(u32);
                    vm.push(u32, @clz(operand));
                },
                .i32_ctz => {
                    const operand = vm.pop(u32);
                    vm.push(u32, @ctz(operand));
                },
                .i32_popcnt => {
                    const operand = vm.pop(u32);
                    vm.push(u32, @popCount(operand));
                },
                .i32_add => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs +% rhs);
                },
                .i32_sub => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs -% rhs);
                },
                .i32_mul => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs *% rhs);
                },
                .i32_div_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, @divTrunc(lhs, rhs));
                },
                .i32_div_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @divTrunc(lhs, rhs));
                },
                .i32_rem_s => {
                    const rhs = vm.pop(i32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, @rem(lhs, rhs));
                },
                .i32_rem_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, @rem(lhs, rhs));
                },
                .i32_and => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs & rhs);
                },
                .i32_or => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs | rhs);
                },
                .i32_xor => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs ^ rhs);
                },
                .i32_shl => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs << @truncate(u5, rhs));
                },
                .i32_shr_s => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(i32);
                    vm.push(i32, lhs >> @truncate(u5, rhs));
                },
                .i32_shr_u => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, lhs >> @truncate(u5, rhs));
                },
                .i32_rotl => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, math.rotl(u32, lhs, rhs % 32));
                },
                .i32_rotr => {
                    const rhs = vm.pop(u32);
                    const lhs = vm.pop(u32);
                    vm.push(u32, math.rotr(u32, lhs, rhs % 32));
                },

                .i64_clz => {
                    const operand = vm.pop(u64);
                    vm.push(u64, @clz(operand));
                },
                .i64_ctz => {
                    const operand = vm.pop(u64);
                    vm.push(u64, @ctz(operand));
                },
                .i64_popcnt => {
                    const operand = vm.pop(u64);
                    vm.push(u64, @popCount(operand));
                },
                .i64_add => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs +% rhs);
                },
                .i64_sub => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs -% rhs);
                },
                .i64_mul => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs *% rhs);
                },
                .i64_div_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, @divTrunc(lhs, rhs));
                },
                .i64_div_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @divTrunc(lhs, rhs));
                },
                .i64_rem_s => {
                    const rhs = vm.pop(i64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, @rem(lhs, rhs));
                },
                .i64_rem_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, @rem(lhs, rhs));
                },
                .i64_and => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs & rhs);
                },
                .i64_or => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs | rhs);
                },
                .i64_xor => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs ^ rhs);
                },
                .i64_shl => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs << @truncate(u6, rhs));
                },
                .i64_shr_s => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(i64);
                    vm.push(i64, lhs >> @truncate(u6, rhs));
                },
                .i64_shr_u => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, lhs >> @truncate(u6, rhs));
                },
                .i64_rotl => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, math.rotl(u64, lhs, rhs % 64));
                },
                .i64_rotr => {
                    const rhs = vm.pop(u64);
                    const lhs = vm.pop(u64);
                    vm.push(u64, math.rotr(u64, lhs, rhs % 64));
                },

                .f32_abs => {
                    vm.push(f32, @fabs(vm.pop(f32)));
                },
                .f32_neg => {
                    vm.push(f32, -vm.pop(f32));
                },
                .f32_ceil => {
                    vm.push(f32, @ceil(vm.pop(f32)));
                },
                .f32_floor => {
                    vm.push(f32, @floor(vm.pop(f32)));
                },
                .f32_trunc => {
                    vm.push(f32, @trunc(vm.pop(f32)));
                },
                .f32_nearest => {
                    vm.push(f32, @round(vm.pop(f32)));
                },
                .f32_sqrt => {
                    vm.push(f32, @sqrt(vm.pop(f32)));
                },
                .f32_add => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs + rhs);
                },
                .f32_sub => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs - rhs);
                },
                .f32_mul => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs * rhs);
                },
                .f32_div => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, lhs / rhs);
                },
                .f32_min => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, @min(lhs, rhs));
                },
                .f32_max => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, @max(lhs, rhs));
                },
                .f32_copysign => {
                    const rhs = vm.pop(f32);
                    const lhs = vm.pop(f32);
                    vm.push(f32, math.copysign(lhs, rhs));
                },
                .f64_abs => {
                    vm.push(f64, @fabs(vm.pop(f64)));
                },
                .f64_neg => {
                    vm.push(f64, -vm.pop(f64));
                },
                .f64_ceil => {
                    vm.push(f64, @ceil(vm.pop(f64)));
                },
                .f64_floor => {
                    vm.push(f64, @floor(vm.pop(f64)));
                },
                .f64_trunc => {
                    vm.push(f64, @trunc(vm.pop(f64)));
                },
                .f64_nearest => {
                    vm.push(f64, @round(vm.pop(f64)));
                },
                .f64_sqrt => {
                    vm.push(f64, @sqrt(vm.pop(f64)));
                },
                .f64_add => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs + rhs);
                },
                .f64_sub => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs - rhs);
                },
                .f64_mul => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs * rhs);
                },
                .f64_div => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, lhs / rhs);
                },
                .f64_min => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, @min(lhs, rhs));
                },
                .f64_max => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, @max(lhs, rhs));
                },
                .f64_copysign => {
                    const rhs = vm.pop(f64);
                    const lhs = vm.pop(f64);
                    vm.push(f64, math.copysign(lhs, rhs));
                },

                .i32_wrap_i64 => {
                    const operand = vm.pop(i64);
                    vm.push(i32, @truncate(i32, operand));
                },
                .i32_trunc_f32_s => {
                    const operand = vm.pop(f32);
                    vm.push(i32, @floatToInt(i32, @trunc(operand)));
                },
                .i32_trunc_f32_u => {
                    const operand = vm.pop(f32);
                    vm.push(u32, @floatToInt(u32, @trunc(operand)));
                },
                .i32_trunc_f64_s => {
                    const operand = vm.pop(f64);
                    vm.push(i32, @floatToInt(i32, @trunc(operand)));
                },
                .i32_trunc_f64_u => {
                    const operand = vm.pop(f64);
                    vm.push(u32, @floatToInt(u32, @trunc(operand)));
                },
                .i64_extend_i32_s => {
                    const operand = vm.pop(i64);
                    vm.push(i64, @truncate(i32, operand));
                },
                .i64_extend_i32_u => {
                    const operand = vm.pop(u64);
                    vm.push(u64, @truncate(u32, operand));
                },
                .i64_trunc_f32_s => {
                    const operand = vm.pop(f32);
                    vm.push(i64, @floatToInt(i64, @trunc(operand)));
                },
                .i64_trunc_f32_u => {
                    const operand = vm.pop(f32);
                    vm.push(u64, @floatToInt(u64, @trunc(operand)));
                },
                .i64_trunc_f64_s => {
                    const operand = vm.pop(f64);
                    vm.push(i64, @floatToInt(i64, @trunc(operand)));
                },
                .i64_trunc_f64_u => {
                    const operand = vm.pop(f64);
                    vm.push(u64, @floatToInt(u64, @trunc(operand)));
                },
                .f32_convert_i32_s => {
                    vm.push(f32, @intToFloat(f32, vm.pop(i32)));
                },
                .f32_convert_i32_u => {
                    vm.push(f32, @intToFloat(f32, vm.pop(u32)));
                },
                .f32_convert_i64_s => {
                    vm.push(f32, @intToFloat(f32, vm.pop(i64)));
                },
                .f32_convert_i64_u => {
                    vm.push(f32, @intToFloat(f32, vm.pop(u64)));
                },
                .f32_demote_f64 => {
                    vm.push(f32, @floatCast(f32, vm.pop(f64)));
                },
                .f64_convert_i32_s => {
                    vm.push(f64, @intToFloat(f64, vm.pop(i32)));
                },
                .f64_convert_i32_u => {
                    vm.push(f64, @intToFloat(f64, vm.pop(u32)));
                },
                .f64_convert_i64_s => {
                    vm.push(f64, @intToFloat(f64, vm.pop(i64)));
                },
                .f64_convert_i64_u => {
                    vm.push(f64, @intToFloat(f64, vm.pop(u64)));
                },
                .f64_promote_f32 => {
                    vm.push(f64, vm.pop(f32));
                },
                .i32_reinterpret_f32 => {
                    vm.push(u32, @bitCast(u32, vm.pop(f32)));
                },
                .i64_reinterpret_f64 => {
                    vm.push(u64, @bitCast(u64, vm.pop(f64)));
                },
                .f32_reinterpret_i32 => {
                    vm.push(f32, @bitCast(f32, vm.pop(u32)));
                },
                .f64_reinterpret_i64 => {
                    vm.push(f64, @bitCast(f64, vm.pop(u64)));
                },

                .i32_extend8_s => {
                    vm.push(i32, @truncate(i8, vm.pop(i32)));
                },
                .i32_extend16_s => {
                    vm.push(i32, @truncate(i16, vm.pop(i32)));
                },
                .i64_extend8_s => {
                    vm.push(i64, @truncate(i8, vm.pop(i64)));
                },
                .i64_extend16_s => {
                    vm.push(i64, @truncate(i16, vm.pop(i64)));
                },
                .i64_extend32_s => {
                    vm.push(i64, @truncate(i32, vm.pop(i64)));
                },
                .prefixed => {
                    const prefixed_op = @intToEnum(wasm.PrefixedOpcode, opcodes[opcode_pc.*]);
                    opcode_pc.* += 1;
                    switch (prefixed_op) {
                        .i32_trunc_sat_f32_s => unreachable,
                        .i32_trunc_sat_f32_u => unreachable,
                        .i32_trunc_sat_f64_s => unreachable,
                        .i32_trunc_sat_f64_u => unreachable,
                        .i64_trunc_sat_f32_s => unreachable,
                        .i64_trunc_sat_f32_u => unreachable,
                        .i64_trunc_sat_f64_s => unreachable,
                        .i64_trunc_sat_f64_u => unreachable,
                        .memory_init => unreachable,
                        .data_drop => unreachable,
                        .memory_copy => {
                            const n = vm.pop(u32);
                            const src = vm.pop(u32);
                            const dest = vm.pop(u32);
                            assert(dest + n <= vm.memory_len);
                            assert(src + n <= vm.memory_len);
                            assert(src + n <= dest or dest + n <= src); // overlapping
                            @memcpy(vm.memory.ptr + dest, vm.memory.ptr + src, n);
                        },
                        .memory_fill => {
                            const n = vm.pop(u32);
                            const value = @truncate(u8, vm.pop(u32));
                            const dest = vm.pop(u32);
                            assert(dest + n <= vm.memory_len);
                            @memset(vm.memory.ptr + dest, value, n);
                        },
                        .table_init => unreachable,
                        .elem_drop => unreachable,
                        .table_copy => unreachable,
                        .table_grow => unreachable,
                        .table_size => unreachable,
                        .table_fill => unreachable,
                        _ => unreachable,
                    }
                },
                _ => unreachable,
            }
        }
    }
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
    const result = @bitCast(f32, std.mem.readIntLittle(i32, bytes[i.*..][0..4]));
    i.* += 4;
    return result;
}

fn readFloat64(bytes: []const u8, i: *u32) f64 {
    const result = @bitCast(f64, std.mem.readIntLittle(i64, bytes[i.*..][0..8]));
    i.* += 8;
    return result;
}

/// fn args_sizes_get(argc: *usize, argv_buf_size: *usize) errno_t;
fn wasi_args_sizes_get(vm: *VirtualMachine, argc: u32, argv_buf_size: u32) wasi.errno_t {
    trace_log.debug("wasi_args_sizes_get argc={d} argv_buf_size={d}", .{ argc, argv_buf_size });
    mem.writeIntLittle(u32, vm.memory[argc..][0..4], @intCast(u32, vm.args.len));
    var buf_size: usize = 0;
    for (vm.args) |arg| {
        buf_size += arg.len + 1;
    }
    mem.writeIntLittle(u32, vm.memory[argv_buf_size..][0..4], @intCast(u32, buf_size));
    return .SUCCESS;
}

/// extern fn args_get(argv: [*][*:0]u8, argv_buf: [*]u8) errno_t;
fn wasi_args_get(vm: *VirtualMachine, argv: u32, argv_buf: u32) wasi.errno_t {
    trace_log.debug("wasi_args_get argv={d} argv_buf={d}", .{ argv, argv_buf });
    var argv_buf_i: usize = 0;
    for (vm.args) |arg, arg_i| {
        // Write the arg to the buffer.
        const argv_ptr = argv_buf + argv_buf_i;
        mem.copy(u8, vm.memory[argv_buf + argv_buf_i ..], arg);
        vm.memory[argv_buf + argv_buf_i + arg.len] = 0;
        argv_buf_i += arg.len + 1;

        mem.writeIntLittle(u32, vm.memory[argv + 4 * arg_i ..][0..4], @intCast(u32, argv_ptr));
    }
    return .SUCCESS;
}

/// extern fn random_get(buf: [*]u8, buf_len: usize) errno_t;
fn wasi_random_get(vm: *VirtualMachine, buf: u32, buf_len: u32) wasi.errno_t {
    const host_buf = vm.memory[buf..][0..buf_len];
    std.crypto.random.bytes(host_buf);
    trace_log.debug("random_get {x}", .{std.fmt.fmtSliceHexLower(host_buf)});
    return .SUCCESS;
}

var preopens_buffer: [10]Preopen = undefined;
var preopens_len: usize = 0;

const Preopen = struct {
    wasi_fd: wasi.fd_t,
    name: []const u8,
    host_fd: os.fd_t,
};

fn addPreopen(wasi_fd: wasi.fd_t, name: []const u8, host_fd: os.fd_t) void {
    preopens_buffer[preopens_len] = .{
        .wasi_fd = wasi_fd,
        .name = name,
        .host_fd = host_fd,
    };
    preopens_len += 1;
}

fn findPreopen(wasi_fd: wasi.fd_t) ?Preopen {
    for (preopens_buffer[0..preopens_len]) |preopen| {
        if (preopen.wasi_fd == wasi_fd) {
            return preopen;
        }
    }
    return null;
}

fn toHostFd(wasi_fd: wasi.fd_t) os.fd_t {
    const preopen = findPreopen(wasi_fd) orelse return wasi_fd;
    return preopen.host_fd;
}

/// fn fd_prestat_get(fd: fd_t, buf: *prestat_t) errno_t;
/// const prestat_t = extern struct {
///     pr_type: u8,
///     u: usize,
/// };
fn wasi_fd_prestat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_prestat_get fd={d} buf={d}", .{ fd, buf });
    const preopen = findPreopen(fd) orelse return .BADF;
    mem.writeIntLittle(u32, vm.memory[buf + 0 ..][0..4], 0);
    mem.writeIntLittle(u32, vm.memory[buf + 4 ..][0..4], @intCast(u32, preopen.name.len));
    return .SUCCESS;
}

/// fn fd_prestat_dir_name(fd: fd_t, path: [*]u8, path_len: usize) errno_t;
fn wasi_fd_prestat_dir_name(vm: *VirtualMachine, fd: wasi.fd_t, path: u32, path_len: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_prestat_dir_name fd={d} path={d} path_len={d}", .{ fd, path, path_len });
    const preopen = findPreopen(fd) orelse return .BADF;
    assert(path_len == preopen.name.len);
    mem.copy(u8, vm.memory[path..], preopen.name);
    return .SUCCESS;
}

/// extern fn fd_close(fd: fd_t) errno_t;
fn wasi_fd_close(vm: *VirtualMachine, fd: wasi.fd_t) wasi.errno_t {
    trace_log.debug("wasi_fd_close fd={d}", .{fd});
    _ = vm;
    const host_fd = toHostFd(fd);
    os.close(host_fd);
    return .SUCCESS;
}

fn wasi_fd_read(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    iovs: u32, // [*]const iovec_t
    iovs_len: u32, // usize
    nread: u32, // *usize
) wasi.errno_t {
    trace_log.debug("wasi_fd_read fd={d} iovs={d} iovs_len={d} nread={d}", .{
        fd, iovs, iovs_len, nread,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var total_read: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 0 ..][0..4]);
        const len = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 4 ..][0..4]);
        const buf = vm.memory[ptr..][0..len];
        const read = os.read(host_fd, buf) catch |err| return toWasiError(err);
        trace_log.debug("read {d} bytes out of {d}", .{ read, buf.len });
        total_read += read;
        if (read != buf.len) break;
    }
    mem.writeIntLittle(u32, vm.memory[nread..][0..4], @intCast(u32, total_read));
    return .SUCCESS;
}

/// extern fn fd_write(fd: fd_t, iovs: [*]const ciovec_t, iovs_len: usize, nwritten: *usize) errno_t;
/// const ciovec_t = extern struct {
///     base: [*]const u8,
///     len: usize,
/// };
fn wasi_fd_write(vm: *VirtualMachine, fd: wasi.fd_t, iovs: u32, iovs_len: u32, nwritten: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_write fd={d} iovs={d} iovs_len={d} nwritten={d}", .{
        fd, iovs, iovs_len, nwritten,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var total_written: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 0 ..][0..4]);
        const len = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 4 ..][0..4]);
        const buf = vm.memory[ptr..][0..len];
        const written = os.write(host_fd, buf) catch |err| return toWasiError(err);
        total_written += written;
        if (written != buf.len) break;
    }
    mem.writeIntLittle(u32, vm.memory[nwritten..][0..4], @intCast(u32, total_written));
    return .SUCCESS;
}

fn wasi_fd_pwrite(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    iovs: u32, // [*]const ciovec_t
    iovs_len: u32, // usize
    offset: wasi.filesize_t,
    written_ptr: u32, // *usize
) wasi.errno_t {
    trace_log.debug("wasi_fd_write fd={d} iovs={d} iovs_len={d} offset={d} written_ptr={d}", .{
        fd, iovs, iovs_len, offset, written_ptr,
    });
    const host_fd = toHostFd(fd);
    var i: u32 = 0;
    var written: usize = 0;
    while (i < iovs_len) : (i += 1) {
        const ptr = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 0 ..][0..4]);
        const len = mem.readIntLittle(u32, vm.memory[iovs + i * 8 + 4 ..][0..4]);
        const buf = vm.memory[ptr..][0..len];
        const w = os.pwrite(host_fd, buf, offset + written) catch |err| return toWasiError(err);
        written += w;
        if (w != buf.len) break;
    }
    mem.writeIntLittle(u32, vm.memory[written_ptr..][0..4], @intCast(u32, written));
    return .SUCCESS;
}

///extern fn path_open(
///    dirfd: fd_t,
///    dirflags: lookupflags_t,
///    path: [*]const u8,
///    path_len: usize,
///    oflags: oflags_t,
///    fs_rights_base: rights_t,
///    fs_rights_inheriting: rights_t,
///    fs_flags: fdflags_t,
///    fd: *fd_t,
///) errno_t;
fn wasi_path_open(
    vm: *VirtualMachine,
    dirfd: wasi.fd_t,
    dirflags: wasi.lookupflags_t,
    path: u32,
    path_len: u32,
    oflags: wasi.oflags_t,
    fs_rights_base: wasi.rights_t,
    fs_rights_inheriting: wasi.rights_t,
    fs_flags: wasi.fdflags_t,
    fd: u32,
) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_open dirfd={d} dirflags={d} path={s} oflags={d} fs_rights_base={d} fs_rights_inheriting={d} fs_flags={d} fd={d}", .{
        dirfd, dirflags, sub_path, oflags, fs_rights_base, fs_rights_inheriting, fs_flags, fd,
    });
    const host_fd = toHostFd(dirfd);
    var flags: u32 = @as(u32, if (oflags & wasi.O.CREAT != 0) os.O.CREAT else 0) |
        @as(u32, if (oflags & wasi.O.DIRECTORY != 0) os.O.DIRECTORY else 0) |
        @as(u32, if (oflags & wasi.O.EXCL != 0) os.O.EXCL else 0) |
        @as(u32, if (oflags & wasi.O.TRUNC != 0) os.O.TRUNC else 0) |
        @as(u32, if (fs_flags & wasi.FDFLAG.APPEND != 0) os.O.APPEND else 0) |
        @as(u32, if (fs_flags & wasi.FDFLAG.DSYNC != 0) os.O.DSYNC else 0) |
        @as(u32, if (fs_flags & wasi.FDFLAG.NONBLOCK != 0) os.O.NONBLOCK else 0) |
        @as(u32, if (fs_flags & wasi.FDFLAG.SYNC != 0) os.O.SYNC else 0);
    if ((fs_rights_base & wasi.RIGHT.FD_READ != 0) and
        (fs_rights_base & wasi.RIGHT.FD_WRITE != 0))
    {
        flags |= os.O.RDWR;
    } else if (fs_rights_base & wasi.RIGHT.FD_WRITE != 0) {
        flags |= os.O.WRONLY;
    } else if (fs_rights_base & wasi.RIGHT.FD_READ != 0) {
        flags |= os.O.RDONLY; // no-op because O_RDONLY is 0
    }
    const mode = 0o644;
    const res_fd = os.openat(host_fd, sub_path, flags, mode) catch |err| return toWasiError(err);
    mem.writeIntLittle(i32, vm.memory[fd..][0..4], res_fd);
    return .SUCCESS;
}

fn wasi_path_filestat_get(
    vm: *VirtualMachine,
    fd: wasi.fd_t,
    flags: wasi.lookupflags_t,
    path: u32, // [*]const u8
    path_len: u32, // usize
    buf: u32, // *filestat_t
) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_filestat_get fd={d} flags={d} path={s} buf={d}", .{
        fd, flags, sub_path, buf,
    });
    const host_fd = toHostFd(fd);
    const dir: fs.Dir = .{ .fd = host_fd };
    const stat = dir.statFile(sub_path) catch |err| return toWasiError(err);
    return finishWasiStat(vm, buf, stat);
}

/// extern fn path_create_directory(fd: fd_t, path: [*]const u8, path_len: usize) errno_t;
fn wasi_path_create_directory(vm: *VirtualMachine, fd: wasi.fd_t, path: u32, path_len: u32) wasi.errno_t {
    const sub_path = vm.memory[path..][0..path_len];
    trace_log.debug("wasi_path_create_directory fd={d} path={s}", .{ fd, sub_path });
    const host_fd = toHostFd(fd);
    const dir: fs.Dir = .{ .fd = host_fd };
    dir.makeDir(sub_path) catch |err| return toWasiError(err);
    return .SUCCESS;
}

fn wasi_path_rename(
    vm: *VirtualMachine,
    old_fd: wasi.fd_t,
    old_path_ptr: u32, // [*]const u8
    old_path_len: u32, // usize
    new_fd: wasi.fd_t,
    new_path_ptr: u32, // [*]const u8
    new_path_len: u32, // usize
) wasi.errno_t {
    const old_path = vm.memory[old_path_ptr..][0..old_path_len];
    const new_path = vm.memory[new_path_ptr..][0..new_path_len];
    trace_log.debug("wasi_path_rename old_fd={d} old_path={s} new_fd={d} new_path={s}", .{
        old_fd, old_path, new_fd, new_path,
    });
    const old_host_fd = toHostFd(old_fd);
    const new_host_fd = toHostFd(new_fd);
    os.renameat(old_host_fd, old_path, new_host_fd, new_path) catch |err| return toWasiError(err);
    return .SUCCESS;
}

/// extern fn fd_filestat_get(fd: fd_t, buf: *filestat_t) errno_t;
fn wasi_fd_filestat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_filestat_get fd={d} buf={d}", .{ fd, buf });
    const host_fd = toHostFd(fd);
    const file = fs.File{ .handle = host_fd };
    const stat = file.stat() catch |err| return toWasiError(err);
    return finishWasiStat(vm, buf, stat);
}

fn wasi_fd_filestat_set_size(vm: *VirtualMachine, fd: wasi.fd_t, size: wasi.filesize_t) wasi.errno_t {
    _ = vm;
    trace_log.debug("wasi_fd_filestat_set_size fd={d} size={d}", .{ fd, size });
    const host_fd = toHostFd(fd);
    os.ftruncate(host_fd, size) catch |err| return toWasiError(err);
    return .SUCCESS;
}

/// pub extern "wasi_snapshot_preview1" fn fd_fdstat_get(fd: fd_t, buf: *fdstat_t) errno_t;
/// pub const fdstat_t = extern struct {
///     fs_filetype: filetype_t, u8
///     fs_flags: fdflags_t, u16
///     fs_rights_base: rights_t, u64
///     fs_rights_inheriting: rights_t, u64
/// };
fn wasi_fd_fdstat_get(vm: *VirtualMachine, fd: wasi.fd_t, buf: u32) wasi.errno_t {
    trace_log.debug("wasi_fd_fdstat_get fd={d} buf={d}", .{ fd, buf });
    const host_fd = toHostFd(fd);
    const file = fs.File{ .handle = host_fd };
    const stat = file.stat() catch |err| return toWasiError(err);
    mem.writeIntLittle(u16, vm.memory[buf + 0x00 ..][0..2], @enumToInt(toWasiFileType(stat.kind)));
    mem.writeIntLittle(u16, vm.memory[buf + 0x02 ..][0..2], 0); // flags
    mem.writeIntLittle(u64, vm.memory[buf + 0x08 ..][0..8], math.maxInt(u64)); // rights_base
    mem.writeIntLittle(u64, vm.memory[buf + 0x10 ..][0..8], math.maxInt(u64)); // rights_inheriting
    return .SUCCESS;
}

/// extern fn clock_time_get(clock_id: clockid_t, precision: timestamp_t, timestamp: *timestamp_t) errno_t;
fn wasi_clock_time_get(vm: *VirtualMachine, clock_id: wasi.clockid_t, precision: wasi.timestamp_t, timestamp: u32) wasi.errno_t {
    //const host_clock_id = toHostClockId(clock_id);
    _ = precision;
    _ = clock_id;
    const wasi_ts = toWasiTimestamp(std.time.nanoTimestamp());
    mem.writeIntLittle(u64, vm.memory[timestamp..][0..8], wasi_ts);
    return .SUCCESS;
}

///pub extern "wasi_snapshot_preview1" fn debug(string: [*:0]const u8, x: u64) void;
fn wasi_debug(vm: *VirtualMachine, text: u32, n: u64) void {
    const s = mem.sliceTo(vm.memory[text..], 0);
    trace_log.debug("wasi_debug: '{s}' number={d} {x}", .{ s, n, n });
}

/// pub extern "wasi_snapshot_preview1" fn debug_slice(ptr: [*]const u8, len: usize) void;
fn wasi_debug_slice(vm: *VirtualMachine, ptr: u32, len: u32) void {
    const s = vm.memory[ptr..][0..len];
    trace_log.debug("wasi_debug_slice: '{s}'", .{s});
}

fn toWasiTimestamp(ns: i128) u64 {
    return @intCast(u64, ns);
}

fn toWasiError(err: anyerror) wasi.errno_t {
    trace_log.warn("wasi error: {s}", .{@errorName(err)});
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.DiskQuota => .DQUOT,
        error.InputOutput => .IO,
        error.FileTooBig => .FBIG,
        error.NoSpaceLeft => .NOSPC,
        error.BrokenPipe => .PIPE,
        error.NotOpenForWriting => .BADF,
        error.SystemResources => .NOMEM,
        error.FileNotFound => .NOENT,
        error.PathAlreadyExists => .EXIST,
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
fn finishWasiStat(vm: *VirtualMachine, buf: u32, stat: fs.File.Stat) wasi.errno_t {
    mem.writeIntLittle(u64, vm.memory[buf + 0x00 ..][0..8], 0); // device
    mem.writeIntLittle(u64, vm.memory[buf + 0x08 ..][0..8], stat.inode);
    mem.writeIntLittle(u64, vm.memory[buf + 0x10 ..][0..8], @enumToInt(toWasiFileType(stat.kind)));
    mem.writeIntLittle(u64, vm.memory[buf + 0x18 ..][0..8], 1); // nlink
    mem.writeIntLittle(u64, vm.memory[buf + 0x20 ..][0..8], stat.size);
    mem.writeIntLittle(u64, vm.memory[buf + 0x28 ..][0..8], toWasiTimestamp(stat.atime));
    mem.writeIntLittle(u64, vm.memory[buf + 0x30 ..][0..8], toWasiTimestamp(stat.mtime));
    mem.writeIntLittle(u64, vm.memory[buf + 0x38 ..][0..8], toWasiTimestamp(stat.ctime));
    return .SUCCESS;
}
