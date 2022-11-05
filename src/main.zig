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
    const import_fn_count = c: {
        i = section_starts[@enumToInt(wasm.Section.import)];
        var count = readVarInt(module_bytes, &i, u32);
        var fn_count: u32 = 0;
        while (count > 0) : (count -= 1) {
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
            fn_count += @boolToInt(desc == .function);
            _ = mod_name;
            _ = sym_name;
        }
        break :c fn_count;
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
                break :i index - import_fn_count;
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

    var exec: Exec = .{
        .section_starts = section_starts,
        .module_bytes = module_bytes,
        .stack_top = 0,
        .functions = functions,
        .types = types,
    };
    exec.initCall(start_fn_idx);
    exec.run();
}

const section_count = @typeInfo(wasm.Section).Enum.fields.len;
var stack: [1 << 10]Value = undefined;

const Function = struct {
    /// Index to start of code in module_bytes.
    code: u32,
    /// Index into types.
    type_idx: u32,
};

const Exec = struct {
    section_starts: [section_count]u32,
    stack_top: u32,
    module_bytes: []const u8,
    current_frame: Frame = Frame.terminus(),
    functions: []const Function,
    /// Type index to start of type in module_bytes.
    types: []const u32,

    fn initCall(e: *Exec, fn_idx: u32) void {
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
            .func = fn_idx,
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

    fn run(e: *Exec) noreturn {
        const module_bytes = e.module_bytes;
        while (true) {
            const op = @intToEnum(wasm.Opcode, module_bytes[e.current_frame.pc]);
            e.current_frame.pc += 1;
            switch (op) {
                .@"unreachable" => @panic("unreachable"),
                .nop => {},
                .block => @panic("unhandled opcode: block"),
                .loop => @panic("unhandled opcode: loop"),
                .@"if" => @panic("unhandled opcode: if"),
                .@"else" => @panic("unhandled opcode: else"),
                .end => @panic("unhandled opcode: end"),
                .br => @panic("unhandled opcode: br"),
                .br_if => @panic("unhandled opcode: br_if"),
                .br_table => @panic("unhandled opcode: br_table"),
                .@"return" => @panic("unhandled opcode: return"),
                .call => @panic("unhandled opcode: call"),
                .call_indirect => @panic("unhandled opcode: call_indirect"),
                .drop => @panic("unhandled opcode: drop"),
                .select => @panic("unhandled opcode: select"),
                .local_get => @panic("unhandled opcode: local_get"),
                .local_set => @panic("unhandled opcode: local_set"),
                .local_tee => @panic("unhandled opcode: local_tee"),
                .global_get => @panic("unhandled opcode: global_get"),
                .global_set => @panic("unhandled opcode: global_set"),
                .i32_load => @panic("unhandled opcode: i32_load"),
                .i64_load => @panic("unhandled opcode: i64_load"),
                .f32_load => @panic("unhandled opcode: f32_load"),
                .f64_load => @panic("unhandled opcode: f64_load"),
                .i32_load8_s => @panic("unhandled opcode: i32_load8_s"),
                .i32_load8_u => @panic("unhandled opcode: i32_load8_u"),
                .i32_load16_s => @panic("unhandled opcode: i32_load16_s"),
                .i32_load16_u => @panic("unhandled opcode: i32_load16_u"),
                .i64_load8_s => @panic("unhandled opcode: i64_load8_s"),
                .i64_load8_u => @panic("unhandled opcode: i64_load8_u"),
                .i64_load16_s => @panic("unhandled opcode: i64_load16_s"),
                .i64_load16_u => @panic("unhandled opcode: i64_load16_u"),
                .i64_load32_s => @panic("unhandled opcode: i64_load32_s"),
                .i64_load32_u => @panic("unhandled opcode: i64_load32_u"),
                .i32_store => @panic("unhandled opcode: i32_store"),
                .i64_store => @panic("unhandled opcode: i64_store"),
                .f32_store => @panic("unhandled opcode: f32_store"),
                .f64_store => @panic("unhandled opcode: f64_store"),
                .i32_store8 => @panic("unhandled opcode: i32_store8"),
                .i32_store16 => @panic("unhandled opcode: i32_store16"),
                .i64_store8 => @panic("unhandled opcode: i64_store8"),
                .i64_store16 => @panic("unhandled opcode: i64_store16"),
                .i64_store32 => @panic("unhandled opcode: i64_store32"),
                .memory_size => @panic("unhandled opcode: memory_size"),
                .memory_grow => @panic("unhandled opcode: memory_grow"),
                .i32_const => @panic("unhandled opcode: i32_const"),
                .i64_const => @panic("unhandled opcode: i64_const"),
                .f32_const => @panic("unhandled opcode: f32_const"),
                .f64_const => @panic("unhandled opcode: f64_const"),
                .i32_eqz => @panic("unhandled opcode: i32_eqz"),
                .i32_eq => @panic("unhandled opcode: i32_eq"),
                .i32_ne => @panic("unhandled opcode: i32_ne"),
                .i32_lt_s => @panic("unhandled opcode: i32_lt_s"),
                .i32_lt_u => @panic("unhandled opcode: i32_lt_u"),
                .i32_gt_s => @panic("unhandled opcode: i32_gt_s"),
                .i32_gt_u => @panic("unhandled opcode: i32_gt_u"),
                .i32_le_s => @panic("unhandled opcode: i32_le_s"),
                .i32_le_u => @panic("unhandled opcode: i32_le_u"),
                .i32_ge_s => @panic("unhandled opcode: i32_ge_s"),
                .i32_ge_u => @panic("unhandled opcode: i32_ge_u"),
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
                .i32_add => @panic("unhandled opcode: i32_add"),
                .i32_sub => @panic("unhandled opcode: i32_sub"),
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
    func: u32,
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
