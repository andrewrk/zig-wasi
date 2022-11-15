const std = @import("std");
const cReader = @import("io/c_reader.zig").cReader;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const wasm = std.wasm;
const wasi = std.os.wasi;
const os = std.os;
const math = std.math;
const leb = std.leb;
const decode_log = std.log.scoped(.decode);
const stats_log = std.log.scoped(.stats);
const trace_log = std.log.scoped(.trace);
const cpu_log = std.log.scoped(.cpu);
const func_log = std.log.scoped(.func);

const SEEK = enum(c_int) { SET, CUR, END };
pub extern "c" fn fseek(stream: *std.c.FILE, offset: c_long, whence: SEEK) c_int;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (scope == .decode) return;
    if (scope == .stats) return;
    if (scope == .cpu) return;
    if (scope == .trace) return;
    if (scope == .func) return;
    std.debug.print(format ++ "\n", args);
    _ = level;
}

const check_stack_types = false;

const max_memory = 3 * 1024 * 1024 * 1024; // 3 GiB

pub export fn main(argc: c_int, argv: [*c][*:0]u8) c_int {
    main2(argv[0..@intCast(usize, argc)]) catch |e| std.debug.print("{s}\n", .{@errorName(e)});
    return 1;
}

fn main2(args: []const [*:0]const u8) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.raw_c_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var vm: VirtualMachine = undefined;
    vm.memory = try os.mmap(
        null,
        max_memory,
        os.PROT.READ | os.PROT.WRITE,
        os.MAP.PRIVATE | os.MAP.ANONYMOUS,
        -1,
        0,
    );

    const zig_lib_dir_path = args[1];
    const wasm_file = args[2];
    vm.args = args[2..];

    const cwd = try fs.cwd().openDir(".", .{});
    const cache_dir = try cwd.makeOpenPath("zig1-cache", .{});
    const zig_lib_dir = try cwd.openDirZ(zig_lib_dir_path, .{}, false);

    addPreopen(0, "stdin", os.STDIN_FILENO);
    addPreopen(1, "stdout", os.STDOUT_FILENO);
    addPreopen(2, "stderr", os.STDERR_FILENO);
    addPreopen(3, ".", cwd.fd);
    addPreopen(4, "/cache", cache_dir.fd);
    addPreopen(5, "/lib", zig_lib_dir.fd);

    var start_fn_idx: u32 = undefined;
    {
        const module_file = std.c.fopen(wasm_file, "rb") orelse return error.FileNotFound;
        defer _ = std.c.fclose(module_file);
        const module_reader = cReader(module_file);

        var magic: [4]u8 = undefined;
        try module_reader.readNoEof(&magic);
        if (!mem.eql(u8, &magic, "\x00asm")) return error.NotWasm;

        const version = try module_reader.readIntLittle(u32);
        if (version != 1) return error.BadWasmVersion;

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .type)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        var max_param_count: u64 = 0;
        vm.types = try arena.alloc(TypeInfo, try leb.readULEB128(u32, module_reader));
        for (vm.types) |*@"type"| {
            assert(try leb.readILEB128(i33, module_reader) == -0x20);

            @"type".param_count = try leb.readULEB128(u32, module_reader);
            assert(@"type".param_count <= 32);
            @"type".param_types = TypeInfo.ParamTypes.initEmpty();
            max_param_count = @max(@"type".param_count, max_param_count);
            var param_index: u32 = 0;
            while (param_index < @"type".param_count) : (param_index += 1) {
                const param_type = try leb.readILEB128(i33, module_reader);
                @"type".param_types.setValue(param_index, switch (param_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }

            @"type".result_count = try leb.readULEB128(u32, module_reader);
            assert(@"type".result_count <= 1);
            @"type".result_types = TypeInfo.ResultTypes.initEmpty();
            var result_index: u32 = 0;
            while (result_index < @"type".result_count) : (result_index += 1) {
                const result_type = try leb.readILEB128(i33, module_reader);
                @"type".result_types.setValue(result_index, switch (result_type) {
                    -1, -3 => false,
                    -2, -4 => true,
                    else => unreachable,
                });
            }
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .import)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            vm.imports = try arena.alloc(Import, try leb.readULEB128(u32, module_reader));

            comptime var max_str_len: usize = 0;
            inline for (.{ Import.Mod, Import.Name }) |Enum| {
                inline for (comptime std.meta.fieldNames(Enum)) |str| {
                    max_str_len = @max(str.len, max_str_len);
                }
            }
            var str_buf: [max_str_len]u8 = undefined;

            for (vm.imports) |*import| {
                const mod = str_buf[0..try leb.readULEB128(u32, module_reader)];
                try module_reader.readNoEof(mod);
                import.mod = std.meta.stringToEnum(Import.Mod, mod).?;

                const name = str_buf[0..try leb.readULEB128(u32, module_reader)];
                try module_reader.readNoEof(name);
                import.name = std.meta.stringToEnum(Import.Name, name).?;

                const kind = @intToEnum(wasm.ExternalKind, try module_reader.readByte());
                const idx = try leb.readULEB128(u32, module_reader);
                switch (kind) {
                    .function => import.type_idx = idx,
                    .table, .memory, .global => unreachable,
                }
            }
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .function)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        vm.functions = try arena.alloc(Function, try leb.readULEB128(u32, module_reader));
        for (vm.functions) |*function|
            function.type_idx = try leb.readULEB128(u32, module_reader);

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .table)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            const table_count = try leb.readULEB128(u32, module_reader);
            if (table_count == 1) {
                assert(try leb.readILEB128(i33, module_reader) == -0x10);
                const limits_kind = try module_reader.readByte();
                vm.table = try arena.alloc(u32, try leb.readULEB128(u32, module_reader));
                switch (limits_kind) {
                    0x00 => {},
                    0x01 => _ = try leb.readULEB128(u32, module_reader),
                    else => unreachable,
                }
            } else assert(table_count == 0);
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .memory)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            assert(try leb.readULEB128(u32, module_reader) == 1);
            const limits_kind = try module_reader.readByte();
            vm.memory_len = try leb.readULEB128(u32, module_reader) * wasm.page_size;
            switch (limits_kind) {
                0x00 => {},
                0x01 => _ = try leb.readULEB128(u32, module_reader),
                else => unreachable,
            }
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .global)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        vm.globals = try arena.alloc(u32, try leb.readULEB128(u32, module_reader));
        for (vm.globals) |*global| {
            assert(try leb.readILEB128(i33, module_reader) == -1);
            _ = @intToEnum(Mutability, try module_reader.readByte());
            assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .i32_const);
            global.* = @bitCast(u32, try leb.readILEB128(i32, module_reader));
            assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .end);
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .@"export")
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var found_start_fn = false;
            const start_name = "_start";
            var str_buf: [start_name.len]u8 = undefined;

            var export_count = try leb.readULEB128(u32, module_reader);
            while (export_count > 0) : (export_count -= 1) {
                const name_len = try leb.readULEB128(u32, module_reader);
                var is_start_fn = false;
                if (name_len == start_name.len) {
                    try module_reader.readNoEof(&str_buf);
                    is_start_fn = mem.eql(u8, &str_buf, start_name);
                    found_start_fn = found_start_fn or is_start_fn;
                } else assert(fseek(module_file, @intCast(c_long, name_len), .CUR) == 0);

                const kind = @intToEnum(wasm.ExternalKind, try module_reader.readByte());
                const idx = try leb.readULEB128(u32, module_reader);
                switch (kind) {
                    .function => if (is_start_fn) {
                        start_fn_idx = idx;
                    },
                    .table, .memory, .global => {},
                }
            }
            assert(found_start_fn);
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .element)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var segment_count = try leb.readULEB128(u32, module_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags = @intCast(u3, try leb.readULEB128(u32, module_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, module_reader) == 0);

                assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .i32_const);
                var offset = @bitCast(u32, try leb.readILEB128(i32, module_reader));
                assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .end);

                const element_type = if (flags & 0b110 != 0b110) idx: {
                    if (flags & 0b010 == 0b010) assert(try module_reader.readByte() == 0x00);
                    break :idx -0x10;
                } else try leb.readILEB128(i33, module_reader);
                assert(element_type == -0x10);

                var element_count = try leb.readULEB128(u32, module_reader);
                while (element_count > 0) : ({
                    offset += 1;
                    element_count -= 1;
                }) {
                    if (flags & 0b010 == 0b010)
                        assert(try module_reader.readByte() == 0xD2);
                    vm.table[offset] = try leb.readULEB128(u32, module_reader);
                    if (flags & 0b010 == 0b010)
                        assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .end);
                }
            }
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .code)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        var max_frame_size: u64 = 0;
        {
            vm.opcodes = try arena.alloc(u8, 5000000);
            vm.operands = try arena.alloc(u32, 5000000);

            assert(try leb.readULEB128(u32, module_reader) == vm.functions.len);
            var pc = ProgramCounter{ .opcode = 0, .operand = 0 };
            for (vm.functions) |*function| {
                _ = try leb.readULEB128(u32, module_reader);

                const type_info = &vm.types[function.type_idx];
                function.locals_count = 0;
                function.local_types = .{};
                try function.local_types.resize(
                    arena,
                    type_info.param_count + function.locals_count,
                    false,
                );
                var it = type_info.param_types.iterator(.{});
                while (it.next()) |index| function.local_types.set(index);

                var local_sets_count = try leb.readULEB128(u32, module_reader);
                while (local_sets_count > 0) : (local_sets_count -= 1) {
                    const set_count = try leb.readULEB128(u32, module_reader);
                    const local_type = try leb.readILEB128(i33, module_reader);
                    function.locals_count += set_count;
                    try function.local_types.resize(
                        arena,
                        type_info.param_count + function.locals_count,
                        switch (local_type) {
                            -1, -3 => false,
                            -2, -4 => true,
                            else => unreachable,
                        },
                    );
                }

                max_frame_size = @max(type_info.param_count + function.locals_count, max_frame_size);

                function.entry_pc = pc;
                try vm.decodeCode(module_reader, function, &pc);
            }

            var opcode_counts = [1]u64{0} ** 0x100;
            var wasm_opcode_counts = [1]u64{0} ** 0x100;
            var wasm_prefixed_opcode_counts = [1]u64{0} ** 0x100;
            var prefix: ?Opcode = null;
            for (vm.opcodes[0..pc.opcode]) |opcode| {
                if (prefix) |pre| {
                    switch (pre) {
                        else => unreachable,
                        .wasm => wasm_opcode_counts[opcode] += 1,
                        .wasm_prefixed => wasm_prefixed_opcode_counts[opcode] += 1,
                    }
                    prefix = null;
                } else switch (@intToEnum(Opcode, opcode)) {
                    else => opcode_counts[opcode] += 1,
                    .wasm, .wasm_prefixed => |opc| prefix = opc,
                }
            }

            stats_log.debug("{} opcodes", .{pc.opcode});
            stats_log.debug("{} operands", .{pc.operand});
            for (opcode_counts) |opcode_count, opcode| {
                if (opcode_count == 0) continue;
                stats_log.debug("{} {s}", .{ opcode_count, @tagName(@intToEnum(Opcode, opcode)) });
            }
            for (wasm_opcode_counts) |wasm_opcode_count, wasm_opcode| {
                if (wasm_opcode_count == 0) continue;
                stats_log.debug("{} {s}", .{
                    wasm_opcode_count,
                    @tagName(@intToEnum(wasm.Opcode, wasm_opcode)),
                });
            }
            for (wasm_prefixed_opcode_counts) |wasm_prefixed_opcode_count, wasm_prefixed_opcode| {
                if (wasm_prefixed_opcode_count == 0) continue;
                stats_log.debug("{} {s}", .{
                    wasm_prefixed_opcode_count,
                    @tagName(@intToEnum(wasm.PrefixedOpcode, wasm_prefixed_opcode)),
                });
            }
            stats_log.debug("{} zero offsets", .{offset_counts[0]});
            stats_log.debug("{} non-zero offsets", .{offset_counts[1]});
            stats_log.debug("{} max offset", .{max_offset});
            stats_log.debug("{} max label depth", .{max_label_depth});
            stats_log.debug("{} max stack depth", .{max_stack_depth});
            stats_log.debug("{} max frame size", .{max_frame_size});
            stats_log.debug("{} max param count", .{max_param_count});
        }

        while (@intToEnum(wasm.Section, try module_reader.readByte()) != .data)
            assert(fseek(module_file, @intCast(c_long, try leb.readULEB128(u32, module_reader)), .CUR) == 0);
        _ = try leb.readULEB128(u32, module_reader);

        {
            var segment_count = try leb.readULEB128(u32, module_reader);
            while (segment_count > 0) : (segment_count -= 1) {
                const flags = @intCast(u2, try leb.readULEB128(u32, module_reader));
                assert(flags & 0b001 == 0b000);
                if (flags & 0b010 == 0b010) assert(try leb.readULEB128(u32, module_reader) == 0);

                assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .i32_const);
                const offset = @bitCast(u32, try leb.readILEB128(i32, module_reader));
                assert(@intToEnum(wasm.Opcode, try module_reader.readByte()) == .end);

                const length = try leb.readULEB128(u32, module_reader);
                try module_reader.readNoEof(vm.memory[offset..][0..length]);
            }
        }
    }

    vm.stack = try arena.alloc(u64, 10000000);
    if (check_stack_types) {
        vm.stack_types = .{};
        try vm.stack_types.resize(arena, 10000000, false);
    }
    vm.stack_top = 0;
    vm.call(start_fn_idx);
    vm.run();
}

const Opcode = enum {
    @"unreachable",
    br_void,
    br_32,
    br_64,
    br_if_nez_void,
    br_if_nez_32,
    br_if_nez_64,
    br_if_eqz_void,
    br_if_eqz_32,
    br_if_eqz_64,
    br_table_void,
    br_table_32,
    br_table_64,
    return_void,
    return_32,
    return_64,
    call,
    drop_32,
    drop_64,
    select_32,
    select_64,
    local_get_32,
    local_get_64,
    local_set_32,
    local_set_64,
    local_tee_32,
    local_tee_64,
    global_get_0_32,
    global_get_32,
    global_set_0_32,
    global_set_32,
    wasm,
    wasm_prefixed,
};

var offset_counts = [2]u64{ 0, 0 };
var max_offset: u64 = 0;

var max_label_depth: u64 = 0;
var max_stack_depth: u64 = 0;

const ProgramCounter = struct { opcode: u32, operand: u32 };

const Mutability = enum { @"const", @"var" };

const TypeInfo = struct {
    const ParamTypes = std.StaticBitSet(1 << 5);
    const ResultTypes = std.StaticBitSet(1);

    param_count: u32,
    param_types: ParamTypes,
    result_count: u32,
    result_types: ResultTypes,
};

const Function = struct {
    entry_pc: ProgramCounter,
    type_idx: u32,
    locals_count: u32,
    local_types: std.DynamicBitSetUnmanaged,
};

const Import = struct {
    const Mod = enum {
        wasi_snapshot_preview1,
    };
    const Name = enum {
        args_get,
        args_sizes_get,
        clock_time_get,
        debug,
        debug_slice,
        environ_get,
        environ_sizes_get,
        fd_close,
        fd_fdstat_get,
        fd_filestat_get,
        fd_filestat_set_size,
        fd_filestat_set_times,
        fd_pread,
        fd_prestat_dir_name,
        fd_prestat_get,
        fd_pwrite,
        fd_read,
        fd_readdir,
        fd_write,
        path_create_directory,
        path_filestat_get,
        path_open,
        path_remove_directory,
        path_rename,
        path_unlink_file,
        proc_exit,
        random_get,
    };

    mod: Mod,
    name: Name,
    type_idx: u32,
};

const Label = struct {
    opcode: wasm.Opcode,
    stack_depth: u32,
    type_info: TypeInfo,
    // this is a maxInt terminated linked list that is stored in the operands array
    ref_list: u32 = math.maxInt(u32),
    extra: union {
        loop_pc: ProgramCounter,
        else_ref: u32,
    } = undefined,

    fn operandCount(self: Label) u32 {
        return if (self.opcode == .loop) self.type_info.param_count else self.type_info.result_count;
    }
    fn operandType(self: Label, index: u32) bool {
        return if (self.opcode == .loop)
            self.type_info.param_types.isSet(index)
        else
            self.type_info.result_types.isSet(index);
    }
};

const VirtualMachine = struct {
    stack: []u64,
    stack_types: if (check_stack_types) std.DynamicBitSetUnmanaged else void,
    /// Points to one after the last stack item.
    stack_top: u32,
    pc: ProgramCounter,
    memory_len: u32,
    opcodes: []u8,
    operands: []u32,
    functions: []Function,
    types: []TypeInfo,
    globals: []u32,
    memory: []u8,
    imports: []Import,
    args: []const [*:0]const u8,
    table: []u32,

    fn decodeCode(vm: *VirtualMachine, reader: anytype, function: *Function, pc: *ProgramCounter) !void {
        const opcodes = vm.opcodes;
        const operands = vm.operands;
        const function_type_info = &vm.types[function.type_idx];

        var unreachable_depth: u32 = 0;
        var stack_depth = function_type_info.param_count + function.locals_count + 2;
        var stack_types: std.StaticBitSet(1 << 12) = undefined;

        var label_i: u32 = 0;
        var labels: [1 << 9]Label = undefined;
        labels[label_i] = .{
            .opcode = .block,
            .stack_depth = stack_depth,
            .type_info = function_type_info.*,
        };

        while (true) {
            const opcode = try reader.readByte();
            var prefixed_opcode: u8 = if (@intToEnum(wasm.Opcode, opcode) == .prefixed)
                @intCast(u8, try leb.readULEB128(u32, reader))
            else
                undefined;
            decode_log.debug("stack_depth = {}, opcode = {s}, prefixed_opcode = {s}", .{
                stack_depth,
                @tagName(@intToEnum(wasm.Opcode, opcode)),
                if (@intToEnum(wasm.Opcode, opcode) == .prefixed)
                    @tagName(@intToEnum(wasm.PrefixedOpcode, prefixed_opcode))
                else
                    "(none)",
            });

            const initial_stack_depth = stack_depth;
            if (unreachable_depth == 0) {
                stack_depth = switch (@intToEnum(wasm.Opcode, opcode)) {
                    .@"unreachable",
                    .nop,
                    .block,
                    .loop,
                    .@"else",
                    .end,
                    .br,
                    .call,
                    .@"return",
                    => stack_depth,

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

                    .prefixed => switch (@intToEnum(wasm.PrefixedOpcode, prefixed_opcode)) {
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
                    },

                    _ => unreachable,
                };
                switch (@intToEnum(wasm.Opcode, opcode)) {
                    .@"unreachable",
                    .nop,
                    .block,
                    .loop,
                    .@"else",
                    .end,
                    .br,
                    .call,
                    .@"return",
                    .@"if",
                    .br_if,
                    .br_table,
                    .call_indirect,
                    .drop,
                    .select,
                    .local_set,
                    .local_get,
                    .local_tee,
                    .global_set,
                    .global_get,
                    .i32_store,
                    .i64_store,
                    .f32_store,
                    .f64_store,
                    .i32_store8,
                    .i32_store16,
                    .i64_store8,
                    .i64_store16,
                    .i64_store32,
                    => {},

                    .i32_const,
                    .f32_const,
                    .memory_size,
                    .i32_load,
                    .f32_load,
                    .i32_load8_s,
                    .i32_load8_u,
                    .i32_load16_s,
                    .i32_load16_u,
                    .memory_grow,
                    .i32_eqz,
                    .i32_clz,
                    .i32_ctz,
                    .i32_popcnt,
                    .i64_eqz,
                    .f32_abs,
                    .f32_neg,
                    .f32_ceil,
                    .f32_floor,
                    .f32_trunc,
                    .f32_nearest,
                    .f32_sqrt,
                    .i32_wrap_i64,
                    .i32_trunc_f32_s,
                    .i32_trunc_f32_u,
                    .i32_trunc_f64_s,
                    .i32_trunc_f64_u,
                    .f32_convert_i32_s,
                    .f32_convert_i32_u,
                    .f32_convert_i64_s,
                    .f32_convert_i64_u,
                    .f32_demote_f64,
                    .i32_reinterpret_f32,
                    .f32_reinterpret_i32,
                    .i32_extend8_s,
                    .i32_extend16_s,
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
                    .f32_add,
                    .f32_sub,
                    .f32_mul,
                    .f32_div,
                    .f32_min,
                    .f32_max,
                    .f32_copysign,
                    => stack_types.unset(stack_depth - 1),

                    .i64_const,
                    .f64_const,
                    .i64_load,
                    .f64_load,
                    .i64_load8_s,
                    .i64_load8_u,
                    .i64_load16_s,
                    .i64_load16_u,
                    .i64_load32_s,
                    .i64_load32_u,
                    .i64_clz,
                    .i64_ctz,
                    .i64_popcnt,
                    .f64_abs,
                    .f64_neg,
                    .f64_ceil,
                    .f64_floor,
                    .f64_trunc,
                    .f64_nearest,
                    .f64_sqrt,
                    .i64_extend_i32_s,
                    .i64_extend_i32_u,
                    .i64_trunc_f32_s,
                    .i64_trunc_f32_u,
                    .i64_trunc_f64_s,
                    .i64_trunc_f64_u,
                    .f64_convert_i32_s,
                    .f64_convert_i32_u,
                    .f64_convert_i64_s,
                    .f64_convert_i64_u,
                    .f64_promote_f32,
                    .i64_reinterpret_f64,
                    .f64_reinterpret_i64,
                    .i64_extend8_s,
                    .i64_extend16_s,
                    .i64_extend32_s,
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
                    .f64_add,
                    .f64_sub,
                    .f64_mul,
                    .f64_div,
                    .f64_min,
                    .f64_max,
                    .f64_copysign,
                    => stack_types.set(stack_depth - 1),

                    .prefixed => switch (@intToEnum(wasm.PrefixedOpcode, prefixed_opcode)) {
                        .memory_init,
                        .memory_copy,
                        .memory_fill,
                        .table_init,
                        .table_copy,
                        .table_fill,
                        .data_drop,
                        .elem_drop,
                        => {},

                        .i32_trunc_sat_f32_s,
                        .i32_trunc_sat_f32_u,
                        .i32_trunc_sat_f64_s,
                        .i32_trunc_sat_f64_u,
                        .table_grow,
                        .table_size,
                        => stack_types.unset(stack_depth - 1),

                        .i64_trunc_sat_f32_s,
                        .i64_trunc_sat_f32_u,
                        .i64_trunc_sat_f64_s,
                        .i64_trunc_sat_f64_u,
                        => stack_types.set(stack_depth - 1),

                        _ => unreachable,
                    },

                    _ => unreachable,
                }
            }

            switch (@intToEnum(wasm.Opcode, opcode)) {
                .@"unreachable" => if (unreachable_depth == 0) {
                    opcodes[pc.opcode] = @enumToInt(Opcode.@"unreachable");
                    pc.opcode += 1;
                },
                .nop => {},
                .block, .loop, .@"if" => |opc| {
                    const block_type = try leb.readILEB128(i33, reader);
                    if (unreachable_depth == 0) {
                        label_i += 1;
                        max_label_depth = @max(label_i, max_label_depth);
                        const label = &labels[label_i];
                        const type_info = if (block_type < 0) TypeInfo{
                            .param_count = 0,
                            .param_types = TypeInfo.ParamTypes.initEmpty(),
                            .result_count = @boolToInt(block_type != -0x40),
                            .result_types = switch (block_type) {
                                -0x40, -1, -3 => TypeInfo.ResultTypes.initEmpty(),
                                -2, -4 => TypeInfo.ResultTypes.initFull(),
                                else => unreachable,
                            },
                        } else vm.types[@intCast(u32, block_type)];
                        label.* = .{
                            .opcode = opc,
                            .stack_depth = stack_depth - type_info.param_count,
                            .type_info = type_info,
                        };
                        switch (opc) {
                            .block => {},
                            .loop => {
                                label.extra = .{ .loop_pc = pc.* };
                            },
                            .@"if" => {
                                opcodes[pc.opcode] = @enumToInt(Opcode.br_if_eqz_void);
                                pc.opcode += 1;
                                operands[pc.operand] = 0;
                                label.extra = .{ .else_ref = pc.operand + 1 };
                                pc.operand += 3;
                            },
                            else => unreachable,
                        }
                    } else unreachable_depth += 1;
                },
                .@"else" => if (unreachable_depth <= 1) {
                    const label = &labels[label_i];
                    assert(label.opcode == .@"if");
                    label.opcode = .@"else";
                    if (unreachable_depth == 0) {
                        const operand_count = label.operandCount();
                        opcodes[pc.opcode] = @enumToInt(switch (operand_count) {
                            0 => Opcode.br_void,
                            1 => switch (label.operandType(0)) {
                                false => Opcode.br_32,
                                true => Opcode.br_64,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        operands[pc.operand + 0] = stack_depth - operand_count - label.stack_depth;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;
                        assert(stack_depth - label.type_info.result_count == label.stack_depth);
                    } else unreachable_depth = 0;
                    operands[label.extra.else_ref + 0] = pc.opcode;
                    operands[label.extra.else_ref + 1] = pc.operand;
                    label.extra = undefined;
                    stack_depth = label.stack_depth + label.type_info.param_count;
                },
                .end => {
                    unreachable_depth -|= 1;
                    if (unreachable_depth == 0) {
                        const label = &labels[label_i];
                        const target_pc = if (label.opcode == .loop) &label.extra.loop_pc else pc;
                        if (label.opcode == .@"if") {
                            operands[label.extra.else_ref + 0] = target_pc.opcode;
                            operands[label.extra.else_ref + 1] = target_pc.operand;
                            label.extra = undefined;
                        }
                        var ref = label.ref_list;
                        while (ref != math.maxInt(u32)) {
                            const next_ref = operands[ref];
                            operands[ref] = target_pc.opcode;
                            operands[ref + 1] = target_pc.operand;
                            ref = next_ref;
                        }
                        stack_depth = label.stack_depth + label.type_info.result_count;

                        if (label_i == 0) {
                            const operand_count = labels[0].operandCount();
                            opcodes[pc.opcode] = @enumToInt(switch (operand_count) {
                                0 => Opcode.return_void,
                                1 => switch (labels[0].operandType(0)) {
                                    false => Opcode.return_32,
                                    true => Opcode.return_64,
                                },
                                else => unreachable,
                            });
                            pc.opcode += 1;
                            operands[pc.operand + 0] = 2 + operand_count;
                            stack_depth -= operand_count;
                            assert(stack_depth == labels[0].stack_depth);
                            operands[pc.operand + 1] = stack_depth;
                            pc.operand += 2;
                            return;
                        }
                        label_i -= 1;
                    }
                },
                .br,
                .br_if,
                => |opc| {
                    const label_idx = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const label = &labels[label_i - label_idx];
                        const operand_count = label.operandCount();
                        opcodes[pc.opcode] = @enumToInt(switch (opc) {
                            .br => switch (operand_count) {
                                0 => Opcode.br_void,
                                1 => switch (label.operandType(0)) {
                                    false => Opcode.br_32,
                                    true => Opcode.br_64,
                                },
                                else => unreachable,
                            },
                            .br_if => switch (label.type_info.result_count) {
                                0 => Opcode.br_if_nez_void,
                                1 => switch (label.operandType(0)) {
                                    false => Opcode.br_if_nez_32,
                                    true => Opcode.br_if_nez_64,
                                },
                                else => unreachable,
                            },
                            else => unreachable,
                        });
                        pc.opcode += 1;
                        operands[pc.operand] = stack_depth - operand_count - label.stack_depth;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;
                    }
                },
                .br_table => {
                    const labels_len = try leb.readULEB128(u32, reader);
                    var i: u32 = 0;
                    while (i <= labels_len) : (i += 1) {
                        const label_idx = try leb.readULEB128(u32, reader);
                        if (unreachable_depth != 0) continue;
                        const label = &labels[label_i - label_idx];
                        const operand_count = label.operandCount();
                        if (i == 0) {
                            opcodes[pc.opcode] = @enumToInt(switch (operand_count) {
                                0 => Opcode.br_table_void,
                                1 => switch (label.operandType(0)) {
                                    false => Opcode.br_table_32,
                                    true => Opcode.br_table_64,
                                },
                                else => unreachable,
                            });
                            pc.opcode += 1;
                            operands[pc.operand] = labels_len;
                            pc.operand += 1;
                        }
                        operands[pc.operand] = stack_depth - operand_count - label.stack_depth;
                        operands[pc.operand + 1] = label.ref_list;
                        label.ref_list = pc.operand + 1;
                        pc.operand += 3;
                    }
                },
                .call => {
                    const fn_id = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode] = @enumToInt(Opcode.call);
                        pc.opcode += 1;
                        operands[pc.operand] = fn_id;
                        pc.operand += 1;
                        const type_info = &vm.types[
                            if (fn_id < vm.imports.len)
                                vm.imports[fn_id].type_idx
                            else
                                vm.functions[fn_id - @intCast(u32, vm.imports.len)].type_idx
                        ];
                        stack_depth -= type_info.param_count;
                        var result_index: u32 = 0;
                        while (result_index < type_info.result_count) : (result_index += 1)
                            stack_types.setValue(
                                stack_depth + result_index,
                                type_info.result_types.isSet(result_index),
                            );
                        stack_depth += type_info.result_count;
                    }
                },
                .call_indirect => {
                    const type_idx = try leb.readULEB128(u32, reader);
                    assert(try leb.readULEB128(u32, reader) == 0);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        const type_info = &vm.types[type_idx];
                        stack_depth -= type_info.param_count;
                        var result_index: u32 = 0;
                        while (result_index < type_info.result_count) : (result_index += 1)
                            stack_types.setValue(
                                stack_depth + result_index,
                                type_info.result_types.isSet(result_index),
                            );
                        stack_depth += type_info.result_count;
                    }
                },
                .@"return" => if (unreachable_depth == 0) {
                    const operand_count = labels[0].operandCount();
                    opcodes[pc.opcode] = @enumToInt(switch (operand_count) {
                        0 => Opcode.return_void,
                        1 => switch (labels[0].operandType(0)) {
                            false => Opcode.return_32,
                            true => Opcode.return_64,
                        },
                        else => unreachable,
                    });
                    pc.opcode += 1;
                    operands[pc.operand] = 2 + stack_depth - labels[0].stack_depth;
                    stack_depth -= operand_count;
                    operands[pc.operand + 1] = stack_depth;
                    pc.operand += 2;
                },
                .local_get,
                .local_set,
                .local_tee,
                => |opc| {
                    const local_idx = try leb.readULEB128(u32, reader);
                    if (unreachable_depth == 0) {
                        const local_type = function.local_types.isSet(local_idx);
                        opcodes[pc.opcode] = @enumToInt(switch (local_type) {
                            false => switch (opc) {
                                .local_get => Opcode.local_get_32,
                                .local_set => Opcode.local_set_32,
                                .local_tee => Opcode.local_tee_32,
                                else => unreachable,
                            },
                            true => switch (opc) {
                                .local_get => Opcode.local_get_64,
                                .local_set => Opcode.local_set_64,
                                .local_tee => Opcode.local_tee_64,
                                else => unreachable,
                            },
                        });
                        pc.opcode += 1;
                        operands[pc.operand] = initial_stack_depth - local_idx;
                        pc.operand += 1;
                        if (opc == .local_get) stack_types.setValue(stack_depth - 1, local_type);
                    }
                },
                .global_get,
                .global_set,
                => |opc| {
                    const global_idx = try leb.readULEB128(u32, reader);
                    assert(global_idx == 0);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode] = @enumToInt(switch (global_idx) {
                            0 => switch (opc) {
                                .global_get => Opcode.global_get_0_32,
                                .global_set => Opcode.global_set_0_32,
                                else => unreachable,
                            },
                            else => switch (opc) {
                                .global_get => Opcode.global_get_32,
                                .global_set => Opcode.global_set_32,
                                else => unreachable,
                            },
                        });
                        pc.opcode += 1;
                        if (global_idx != 0) {
                            operands[pc.operand] = global_idx;
                            pc.operand += 1;
                        }
                    }
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
                    const alignment = try leb.readULEB128(u32, reader);
                    const offset = try leb.readULEB128(u32, reader);
                    _ = alignment;
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        operands[pc.operand] = offset;
                        offset_counts[@boolToInt(operands[pc.operand] != 0)] += 1;
                        max_offset = @max(operands[pc.operand], max_offset);
                        pc.operand += 1;
                    }
                },
                .memory_size, .memory_grow => {
                    assert(try reader.readByte() == 0);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                    }
                },
                .i32_const => {
                    const x = @bitCast(u32, try leb.readILEB128(i32, reader));
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        operands[pc.operand] = x;
                        pc.operand += 1;
                    }
                },
                .i64_const => {
                    const x = @bitCast(u64, try leb.readILEB128(i64, reader));
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        operands[pc.operand] = @truncate(u32, x);
                        operands[pc.operand + 1] = @truncate(u32, x >> 32);
                        pc.operand += 2;
                    }
                },
                .f32_const => {
                    const x = try reader.readIntLittle(u32);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        operands[pc.operand] = x;
                        pc.operand += 1;
                    }
                },
                .f64_const => {
                    const x = try reader.readIntLittle(u64);
                    if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                        opcodes[pc.opcode + 1] = opcode;
                        pc.opcode += 2;
                        operands[pc.operand] = @truncate(u32, x);
                        operands[pc.operand + 1] = @truncate(u32, x >> 32);
                        pc.operand += 2;
                    }
                },
                .select,
                .drop,
                => |opc| if (unreachable_depth == 0) {
                    opcodes[pc.opcode] = @enumToInt(switch (stack_types.isSet(stack_depth)) {
                        false => switch (opc) {
                            .select => Opcode.select_32,
                            .drop => Opcode.drop_32,
                            else => unreachable,
                        },
                        true => switch (opc) {
                            .select => Opcode.select_64,
                            .drop => Opcode.drop_64,
                            else => unreachable,
                        },
                    });
                    pc.opcode += 1;
                },
                else => if (unreachable_depth == 0) {
                    opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm);
                    opcodes[pc.opcode + 1] = opcode;
                    pc.opcode += 2;
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
                    => if (unreachable_depth == 0) {
                        opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm_prefixed);
                        opcodes[pc.opcode + 1] = prefixed_opcode;
                        pc.opcode += 2;
                    },
                    .memory_copy => {
                        assert(try reader.readByte() == 0 and try reader.readByte() == 0);
                        if (unreachable_depth == 0) {
                            opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm_prefixed);
                            opcodes[pc.opcode + 1] = prefixed_opcode;
                            pc.opcode += 2;
                        }
                    },
                    .memory_fill => {
                        assert(try reader.readByte() == 0);
                        if (unreachable_depth == 0) {
                            opcodes[pc.opcode + 0] = @enumToInt(Opcode.wasm_prefixed);
                            opcodes[pc.opcode + 1] = prefixed_opcode;
                            pc.opcode += 2;
                        }
                    },
                    else => unreachable,
                },
            }

            max_stack_depth = @max(stack_depth, max_stack_depth);
            switch (@intToEnum(wasm.Opcode, opcode)) {
                .@"unreachable",
                .@"return",
                .br,
                .br_table,
                => if (unreachable_depth == 0) {
                    unreachable_depth = 1;
                },
                else => {},
            }
        }
    }

    fn br(vm: *VirtualMachine, comptime Result: type) void {
        const stack_adjust = vm.operands[vm.pc.operand];

        const result = vm.pop(Result);
        vm.stack_top -= stack_adjust;
        vm.push(Result, result);

        vm.pc.opcode = vm.operands[vm.pc.operand + 1];
        vm.pc.operand = vm.operands[vm.pc.operand + 2];
    }

    fn @"return"(vm: *VirtualMachine, comptime Result: type) void {
        const ret_pc_offset = vm.operands[vm.pc.operand + 0];
        const stack_adjust = vm.operands[vm.pc.operand + 1];

        vm.pc.opcode = @intCast(u32, vm.stack[vm.stack_top - ret_pc_offset]);
        vm.pc.operand = @intCast(u32, vm.stack[vm.stack_top - ret_pc_offset + 1]);

        const result = vm.pop(Result);
        vm.stack_top -= stack_adjust;
        vm.push(Result, result);
    }

    fn call(vm: *VirtualMachine, fn_id: u32) void {
        if (fn_id < vm.imports.len) {
            const imp = vm.imports[fn_id];
            return callImport(vm, imp);
        }
        const fn_idx = fn_id - @intCast(u32, vm.imports.len);
        const func = &vm.functions[fn_idx];

        const type_info = &vm.types[func.type_idx];
        func_log.debug("enter fn_id: {d}, param_count: {d}, result_count: {d}, locals_count: {d}", .{
            fn_id, type_info.param_count, type_info.result_count, func.locals_count,
        });

        // Push zeroed locals to stack
        mem.set(u64, vm.stack[vm.stack_top..][0..func.locals_count], 0);
        vm.stack_top += func.locals_count;

        vm.push(u32, vm.pc.opcode);
        vm.push(u32, vm.pc.operand);

        vm.pc = func.entry_pc;
    }

    fn callImport(vm: *VirtualMachine, import: Import) void {
        switch (import.mod) {
            .wasi_snapshot_preview1 => switch (import.name) {
                .fd_prestat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_prestat_get(vm, fd, buf)));
                },
                .fd_prestat_dir_name => {
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_prestat_dir_name(vm, fd, path, path_len)));
                },
                .fd_close => {
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_close(vm, fd)));
                },
                .fd_read => {
                    const nread = vm.pop(u32);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_read(vm, fd, iovs, iovs_len, nread)));
                },
                .fd_filestat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_filestat_get(vm, fd, buf)));
                },
                .fd_filestat_set_size => {
                    const size = vm.pop(u64);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_filestat_set_size(vm, fd, size)));
                },
                .fd_filestat_set_times => {
                    @panic("TODO implement fd_filestat_set_times");
                },
                .fd_fdstat_get => {
                    const buf = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_fdstat_get(vm, fd, buf)));
                },
                .fd_readdir => {
                    @panic("TODO implement fd_readdir");
                },
                .fd_write => {
                    const nwritten = vm.pop(u32);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_write(vm, fd, iovs, iovs_len, nwritten)));
                },
                .fd_pwrite => {
                    const nwritten = vm.pop(u32);
                    const offset = vm.pop(u64);
                    const iovs_len = vm.pop(u32);
                    const iovs = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_fd_pwrite(vm, fd, iovs, iovs_len, offset, nwritten)));
                },
                .proc_exit => {
                    stats_log.debug("memory length = {}\n", .{vm.memory_len});
                    std.c.exit(@intCast(c_int, vm.pop(wasi.exitcode_t)));
                    unreachable;
                },
                .args_sizes_get => {
                    const argv_buf_size = vm.pop(u32);
                    const argc = vm.pop(u32);
                    vm.push(u32, @enumToInt(wasi_args_sizes_get(vm, argc, argv_buf_size)));
                },
                .args_get => {
                    const argv_buf = vm.pop(u32);
                    const argv = vm.pop(u32);
                    vm.push(u32, @enumToInt(wasi_args_get(vm, argv, argv_buf)));
                },
                .random_get => {
                    const buf_len = vm.pop(u32);
                    const buf = vm.pop(u32);
                    vm.push(u32, @enumToInt(wasi_random_get(vm, buf, buf_len)));
                },
                .environ_sizes_get => {
                    @panic("TODO implement environ_sizes_get");
                },
                .environ_get => {
                    @panic("TODO implement environ_get");
                },
                .path_filestat_get => {
                    const buf = vm.pop(u32);
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const flags = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_path_filestat_get(vm, fd, flags, path, path_len, buf)));
                },
                .path_create_directory => {
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_path_create_directory(vm, fd, path, path_len)));
                },
                .path_rename => {
                    const new_path_len = vm.pop(u32);
                    const new_path = vm.pop(u32);
                    const new_fd = vm.pop(i32);
                    const old_path_len = vm.pop(u32);
                    const old_path = vm.pop(u32);
                    const old_fd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_path_rename(
                        vm,
                        old_fd,
                        old_path,
                        old_path_len,
                        new_fd,
                        new_path,
                        new_path_len,
                    )));
                },
                .path_open => {
                    const fd = vm.pop(u32);
                    const fs_flags = vm.pop(u32);
                    const fs_rights_inheriting = vm.pop(u64);
                    const fs_rights_base = vm.pop(u64);
                    const oflags = vm.pop(u32);
                    const path_len = vm.pop(u32);
                    const path = vm.pop(u32);
                    const dirflags = vm.pop(u32);
                    const dirfd = vm.pop(i32);
                    vm.push(u32, @enumToInt(wasi_path_open(
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
                },
                .path_remove_directory => {
                    @panic("TODO implement path_remove_directory");
                },
                .path_unlink_file => {
                    @panic("TODO implement path_unlink_file");
                },
                .clock_time_get => {
                    const timestamp = vm.pop(u32);
                    const precision = vm.pop(u64);
                    const clock_id = vm.pop(u32);
                    vm.push(u32, @enumToInt(wasi_clock_time_get(vm, clock_id, precision, timestamp)));
                },
                .fd_pread => {
                    @panic("TODO implement fd_pread");
                },
                .debug => {
                    const number = vm.pop(u64);
                    const text = vm.pop(u32);
                    wasi_debug(vm, text, number);
                },
                .debug_slice => {
                    const len = vm.pop(u32);
                    const ptr = vm.pop(u32);
                    wasi_debug_slice(vm, ptr, len);
                },
            },
        }
    }

    fn push(vm: *VirtualMachine, comptime T: type, value: T) void {
        if (@sizeOf(T) == 0) return;
        if (check_stack_types) vm.stack_types.setValue(vm.stack_top, switch (@bitSizeOf(T)) {
            32 => false,
            64 => true,
            else => unreachable,
        });
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
        if (@sizeOf(T) == 0) return undefined;
        vm.stack_top -= 1;
        if (check_stack_types and vm.stack_types.isSet(vm.stack_top) != switch (@bitSizeOf(T)) {
            32 => false,
            64 => true,
            else => unreachable,
        }) @panic("stack type check failure");
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
        const pc = &vm.pc;
        while (true) {
            const op = @intToEnum(Opcode, opcodes[pc.opcode]);
            pc.opcode += 1;
            if (vm.stack_top > 0) {
                cpu_log.debug("stack[{d}]={x} pc={d}:{d}, op={s}", .{
                    vm.stack_top - 1, vm.stack[vm.stack_top - 1], pc.opcode, pc.operand, @tagName(op),
                });
            } else {
                cpu_log.debug("<empty> pc={d}:{d}, op={s}", .{ pc.opcode, pc.operand, @tagName(op) });
            }
            switch (op) {
                .@"unreachable" => @panic("unreachable reached"),
                .br_void => {
                    vm.br(void);
                },
                .br_32 => {
                    vm.br(u32);
                },
                .br_64 => {
                    vm.br(u64);
                },
                .br_if_nez_void => {
                    if (vm.pop(u32) != 0) {
                        vm.br(void);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_if_nez_32 => {
                    if (vm.pop(u32) != 0) {
                        vm.br(u32);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_if_nez_64 => {
                    if (vm.pop(u32) != 0) {
                        vm.br(u64);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_if_eqz_void => {
                    if (vm.pop(u32) == 0) {
                        vm.br(void);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_if_eqz_32 => {
                    if (vm.pop(u32) == 0) {
                        vm.br(u32);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_if_eqz_64 => {
                    if (vm.pop(u32) == 0) {
                        vm.br(u64);
                    } else {
                        pc.operand += 3;
                    }
                },
                .br_table_void => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(void);
                },
                .br_table_32 => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(u32);
                },
                .br_table_64 => {
                    const index = @min(vm.pop(u32), operands[pc.operand]);
                    pc.operand += 1 + index * 3;
                    vm.br(u64);
                },
                .return_void => {
                    vm.@"return"(void);
                },
                .return_32 => {
                    vm.@"return"(u32);
                },
                .return_64 => {
                    vm.@"return"(u64);
                },
                .call => {
                    const fn_id = operands[pc.operand];
                    pc.operand += 1;
                    vm.call(fn_id);
                },
                .drop_32, .drop_64 => {
                    vm.stack_top -= 1;
                },
                .select_32 => {
                    const c = vm.pop(u32);
                    const b = vm.pop(u32);
                    const a = vm.pop(u32);
                    const result = if (c != 0) a else b;
                    vm.push(u32, result);
                },
                .select_64 => {
                    const c = vm.pop(u32);
                    const b = vm.pop(u64);
                    const a = vm.pop(u64);
                    const result = if (c != 0) a else b;
                    vm.push(u64, result);
                },
                .local_get_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    vm.push(u32, @intCast(u32, local.*));
                },
                .local_get_64 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    vm.push(u64, local.*);
                },
                .local_set_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    local.* = vm.pop(u32);
                },
                .local_set_64 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    local.* = vm.pop(u64);
                },
                .local_tee_32 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    if (check_stack_types and vm.stack_types.isSet(vm.stack_top - 1))
                        @panic("stack type check failure");
                    local.* = vm.stack[vm.stack_top - 1];
                },
                .local_tee_64 => {
                    const local = &vm.stack[vm.stack_top - operands[pc.operand]];
                    pc.operand += 1;
                    if (check_stack_types and !vm.stack_types.isSet(vm.stack_top - 1))
                        @panic("stack type check failure");
                    local.* = vm.stack[vm.stack_top - 1];
                },
                .global_get_0_32 => {
                    vm.push(u32, vm.globals[0]);
                },
                .global_get_32 => {
                    const idx = operands[pc.operand];
                    pc.operand += 1;
                    vm.push(u32, vm.globals[idx]);
                },
                .global_set_0_32 => {
                    vm.globals[0] = vm.pop(u32);
                },
                .global_set_32 => {
                    const idx = operands[pc.operand];
                    pc.operand += 1;
                    vm.globals[idx] = vm.pop(u32);
                },
                .wasm => {
                    const wasm_op = @intToEnum(wasm.Opcode, opcodes[pc.opcode]);
                    cpu_log.debug("op2={s}", .{@tagName(wasm_op)});
                    pc.opcode += 1;
                    switch (wasm_op) {
                        .@"unreachable",
                        .nop,
                        .block,
                        .loop,
                        .@"if",
                        .@"else",
                        .end,
                        .br,
                        .br_if,
                        .br_table,
                        .@"return",
                        .call,
                        .drop,
                        .select,
                        .local_get,
                        .local_set,
                        .local_tee,
                        .global_get,
                        .global_set,
                        .prefixed,
                        => @panic("not produced by decodeCode"),

                        .call_indirect => {
                            const fn_id = vm.table[vm.pop(u32)];
                            vm.call(fn_id);
                        },
                        .i32_load => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(u32, mem.readIntLittle(u32, vm.memory[offset..][0..4]));
                        },
                        .i64_load => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(u64, mem.readIntLittle(u64, vm.memory[offset..][0..8]));
                        },
                        .f32_load => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(u32, vm.memory[offset..][0..4]);
                            vm.push(u32, int);
                        },
                        .f64_load => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(u64, vm.memory[offset..][0..8]);
                            vm.push(u64, int);
                        },
                        .i32_load8_s => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(i32, @bitCast(i8, vm.memory[offset]));
                        },
                        .i32_load8_u => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(u32, vm.memory[offset]);
                        },
                        .i32_load16_s => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(i16, vm.memory[offset..][0..2]);
                            vm.push(i32, int);
                        },
                        .i32_load16_u => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(u16, vm.memory[offset..][0..2]);
                            vm.push(u32, int);
                        },
                        .i64_load8_s => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(i64, @bitCast(i8, vm.memory[offset]));
                        },
                        .i64_load8_u => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.push(u64, vm.memory[offset]);
                        },
                        .i64_load16_s => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(i16, vm.memory[offset..][0..2]);
                            vm.push(i64, int);
                        },
                        .i64_load16_u => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(u16, vm.memory[offset..][0..2]);
                            vm.push(u64, int);
                        },
                        .i64_load32_s => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(i32, vm.memory[offset..][0..4]);
                            vm.push(i64, int);
                        },
                        .i64_load32_u => {
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            const int = mem.readIntLittle(u32, vm.memory[offset..][0..4]);
                            vm.push(u64, int);
                        },
                        .i32_store => {
                            const operand = vm.pop(u32);
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u32, vm.memory[offset..][0..4], operand);
                        },
                        .i64_store => {
                            const operand = vm.pop(u64);
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u64, vm.memory[offset..][0..8], operand);
                        },
                        .f32_store => {
                            const int = @bitCast(u32, vm.pop(f32));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u32, vm.memory[offset..][0..4], int);
                        },
                        .f64_store => {
                            const int = @bitCast(u64, vm.pop(f64));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u64, vm.memory[offset..][0..8], int);
                        },
                        .i32_store8 => {
                            const small = @truncate(u8, vm.pop(u32));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.memory[offset] = small;
                        },
                        .i32_store16 => {
                            const small = @truncate(u16, vm.pop(u32));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u16, vm.memory[offset..][0..2], small);
                        },
                        .i64_store8 => {
                            const operand = @truncate(u8, vm.pop(u64));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            vm.memory[offset] = operand;
                        },
                        .i64_store16 => {
                            const small = @truncate(u16, vm.pop(u64));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
                            mem.writeIntLittle(u16, vm.memory[offset..][0..2], small);
                        },
                        .i64_store32 => {
                            const small = @truncate(u32, vm.pop(u64));
                            const offset = operands[pc.operand] + vm.pop(u32);
                            pc.operand += 1;
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
                            const x = operands[pc.operand];
                            pc.operand += 1;
                            vm.push(i32, @bitCast(i32, x));
                        },
                        .i64_const => {
                            const x = operands[pc.operand] | @as(u64, operands[pc.operand + 1]) << 32;
                            pc.operand += 2;
                            vm.push(i64, @bitCast(i64, x));
                        },
                        .f32_const => {
                            const x = operands[pc.operand];
                            pc.operand += 1;
                            vm.push(f32, @bitCast(f32, x));
                        },
                        .f64_const => {
                            const x = operands[pc.operand] | @as(u64, operands[pc.operand + 1]) << 32;
                            pc.operand += 2;
                            vm.push(f64, @bitCast(f64, x));
                        },
                        .i32_eqz => {
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs == 0));
                        },
                        .i32_eq => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs == rhs));
                        },
                        .i32_ne => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs != rhs));
                        },
                        .i32_lt_s => {
                            const rhs = vm.pop(i32);
                            const lhs = vm.pop(i32);
                            vm.push(u32, @boolToInt(lhs < rhs));
                        },
                        .i32_lt_u => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs < rhs));
                        },
                        .i32_gt_s => {
                            const rhs = vm.pop(i32);
                            const lhs = vm.pop(i32);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .i32_gt_u => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .i32_le_s => {
                            const rhs = vm.pop(i32);
                            const lhs = vm.pop(i32);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .i32_le_u => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .i32_ge_s => {
                            const rhs = vm.pop(i32);
                            const lhs = vm.pop(i32);
                            vm.push(u32, @boolToInt(lhs >= rhs));
                        },
                        .i32_ge_u => {
                            const rhs = vm.pop(u32);
                            const lhs = vm.pop(u32);
                            vm.push(u32, @boolToInt(lhs >= rhs));
                        },
                        .i64_eqz => {
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs == 0));
                        },
                        .i64_eq => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs == rhs));
                        },
                        .i64_ne => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs != rhs));
                        },
                        .i64_lt_s => {
                            const rhs = vm.pop(i64);
                            const lhs = vm.pop(i64);
                            vm.push(u32, @boolToInt(lhs < rhs));
                        },
                        .i64_lt_u => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs < rhs));
                        },
                        .i64_gt_s => {
                            const rhs = vm.pop(i64);
                            const lhs = vm.pop(i64);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .i64_gt_u => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .i64_le_s => {
                            const rhs = vm.pop(i64);
                            const lhs = vm.pop(i64);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .i64_le_u => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .i64_ge_s => {
                            const rhs = vm.pop(i64);
                            const lhs = vm.pop(i64);
                            vm.push(u32, @boolToInt(lhs >= rhs));
                        },
                        .i64_ge_u => {
                            const rhs = vm.pop(u64);
                            const lhs = vm.pop(u64);
                            vm.push(u32, @boolToInt(lhs >= rhs));
                        },
                        .f32_eq => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs == rhs));
                        },
                        .f32_ne => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs != rhs));
                        },
                        .f32_lt => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs < rhs));
                        },
                        .f32_gt => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .f32_le => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .f32_ge => {
                            const rhs = vm.pop(f32);
                            const lhs = vm.pop(f32);
                            vm.push(u32, @boolToInt(lhs >= rhs));
                        },
                        .f64_eq => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs == rhs));
                        },
                        .f64_ne => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs != rhs));
                        },
                        .f64_lt => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .f64_gt => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs > rhs));
                        },
                        .f64_le => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs <= rhs));
                        },
                        .f64_ge => {
                            const rhs = vm.pop(f64);
                            const lhs = vm.pop(f64);
                            vm.push(u32, @boolToInt(lhs >= rhs));
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
                            const operand = vm.pop(i32);
                            vm.push(i64, operand);
                        },
                        .i64_extend_i32_u => {
                            const operand = vm.pop(u32);
                            vm.push(u64, operand);
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

                        _ => unreachable,
                    }
                },
                .wasm_prefixed => {
                    const wasm_prefixed_op = @intToEnum(wasm.PrefixedOpcode, opcodes[pc.opcode]);
                    cpu_log.debug("op2={s}", .{@tagName(wasm_prefixed_op)});
                    pc.opcode += 1;
                    switch (wasm_prefixed_op) {
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
            }
        }
    }
};

/// fn args_sizes_get(argc: *usize, argv_buf_size: *usize) errno_t;
fn wasi_args_sizes_get(vm: *VirtualMachine, argc: u32, argv_buf_size: u32) wasi.errno_t {
    trace_log.debug("wasi_args_sizes_get argc={d} argv_buf_size={d}", .{ argc, argv_buf_size });
    mem.writeIntLittle(u32, vm.memory[argc..][0..4], @intCast(u32, vm.args.len));
    var buf_size: usize = 0;
    for (vm.args) |arg| {
        buf_size += mem.span(arg).len + 1;
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
        const arg_len = mem.span(arg).len + 1;
        mem.copy(u8, vm.memory[argv_buf + argv_buf_i ..], arg[0..arg_len]);
        argv_buf_i += arg_len;

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
