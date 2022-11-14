// TODO get rid of _GNU_SOURCE
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static void panic(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    abort();
}

static void *arena_alloc(size_t n) {
    void *ptr = malloc(n);
    if (!ptr) panic("out of memory");
    return ptr;
}

static int err_wrap(const char *prefix, int rc) {
    if (rc == -1) {
        perror(prefix);
        abort();
    }
    return rc;
}

struct ByteSlice {
    char *ptr;
    size_t len;
};

static struct ByteSlice read_file_alloc(const char *file_path) {
    FILE *f = fopen(file_path, "rb");
    if (!f) {
        fprintf(stderr, "failed to read %s: ", file_path);
        perror("");
        abort();
    }
    if (fseek(f, 0L, SEEK_END) == -1) panic("failed to seek");
    struct ByteSlice res;
    res.len = ftell(f);
    res.ptr = malloc(res.len);
    rewind(f);
    size_t amt_read = fread(res.ptr, 1, res.len, f);
    if (amt_read != res.len) panic("short read");
    fclose(f);
    return res;
}


struct Preopen {
    int wasi_fd; 
    int host_fd;
    const char *name;
    size_t name_len;
};

static struct Preopen preopens_buffer[10];
static size_t preopens_len = 0;

static void add_preopen(int wasi_fd, const char *name, int host_fd) {
    preopens_buffer[preopens_len].wasi_fd = wasi_fd;
    preopens_buffer[preopens_len].host_fd = host_fd;
    preopens_buffer[preopens_len].name = name;
    preopens_buffer[preopens_len].name_len = strlen(name);
    preopens_len += 1;
}

static const size_t max_memory = 2ul * 1024ul * 1024ul * 1024ul; // 2 GiB

static uint32_t read32le(const char *ptr) {
    // TODO big endian
    return *((uint32_t *)ptr);
}

static uint32_t read32_uleb128(const char *ptr, uint32_t *i) {
    uint32_t result = 0;
    uint32_t shift = 0;

    for (;;) {
        uint32_t byte = ptr[*i];
        *i += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) return result;
        if (shift >= 32) panic("read32_uleb128 failed");
    }
}

static int64_t read64_ileb128(const char *ptr, uint32_t *i) {
    int64_t result = 0;
    uint32_t shift = 0;

    for (;;) {
        uint64_t byte = ptr[*i];
        *i += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if ((byte & 0x40) && (shift < 64)) {
                uint64_t extend = 0;
                result |= (~extend << shift);
            }
            return result;
        }
        if (shift >= 64) panic("read64_ileb128 failed");
    }
}

static int32_t read32_ileb128(const char *ptr, uint32_t *i) {
    return read64_ileb128(ptr, i);
}

static struct ByteSlice read_name(char *ptr, uint32_t *i) {
    uint32_t len = read32_uleb128(ptr, i);
    struct ByteSlice res;
    res.ptr = ptr + *i;
    res.len = len;
    *i += len;
    return res;
}

static float read_f32(const char *ptr, uint32_t *i) {
    float result;
    memcpy(&result, ptr + *i, 4);
    *i += 4;
    return result;
}

static double read_f64(const char *ptr, uint32_t *i) {
    double result;
    memcpy(&result, ptr + *i, 8);
    *i += 8;
    return result;
}

enum Section {
    Section_custom,
    Section_type,
    Section_import,
    Section_function,
    Section_table,
    Section_memory,
    Section_global,
    Section_export,
    Section_start,
    Section_element,
    Section_code,
    Section_data,
    Section_data_count,
};

enum Op {
    Op_unreachable = 0x00,
    Op_nop = 0x01,
    Op_block = 0x02,
    Op_loop = 0x03,
    Op_if = 0x04,
    Op_else = 0x05,
    Op_end = 0x0B,
    Op_br = 0x0C,
    Op_br_if = 0x0D,
    Op_br_table = 0x0E,
    Op_return = 0x0F,
    Op_call = 0x10,
    Op_call_indirect = 0x11,
    Op_drop = 0x1A,
    Op_select = 0x1B,
    Op_local_get = 0x20,
    Op_local_set = 0x21,
    Op_local_tee = 0x22,
    Op_global_get = 0x23,
    Op_global_set = 0x24,
    Op_i32_load = 0x28,
    Op_i64_load = 0x29,
    Op_f32_load = 0x2A,
    Op_f64_load = 0x2B,
    Op_i32_load8_s = 0x2C,
    Op_i32_load8_u = 0x2D,
    Op_i32_load16_s = 0x2E,
    Op_i32_load16_u = 0x2F,
    Op_i64_load8_s = 0x30,
    Op_i64_load8_u = 0x31,
    Op_i64_load16_s = 0x32,
    Op_i64_load16_u = 0x33,
    Op_i64_load32_s = 0x34,
    Op_i64_load32_u = 0x35,
    Op_i32_store = 0x36,
    Op_i64_store = 0x37,
    Op_f32_store = 0x38,
    Op_f64_store = 0x39,
    Op_i32_store8 = 0x3A,
    Op_i32_store16 = 0x3B,
    Op_i64_store8 = 0x3C,
    Op_i64_store16 = 0x3D,
    Op_i64_store32 = 0x3E,
    Op_memory_size = 0x3F,
    Op_memory_grow = 0x40,
    Op_i32_const = 0x41,
    Op_i64_const = 0x42,
    Op_f32_const = 0x43,
    Op_f64_const = 0x44,
    Op_i32_eqz = 0x45,
    Op_i32_eq = 0x46,
    Op_i32_ne = 0x47,
    Op_i32_lt_s = 0x48,
    Op_i32_lt_u = 0x49,
    Op_i32_gt_s = 0x4A,
    Op_i32_gt_u = 0x4B,
    Op_i32_le_s = 0x4C,
    Op_i32_le_u = 0x4D,
    Op_i32_ge_s = 0x4E,
    Op_i32_ge_u = 0x4F,
    Op_i64_eqz = 0x50,
    Op_i64_eq = 0x51,
    Op_i64_ne = 0x52,
    Op_i64_lt_s = 0x53,
    Op_i64_lt_u = 0x54,
    Op_i64_gt_s = 0x55,
    Op_i64_gt_u = 0x56,
    Op_i64_le_s = 0x57,
    Op_i64_le_u = 0x58,
    Op_i64_ge_s = 0x59,
    Op_i64_ge_u = 0x5A,
    Op_f32_eq = 0x5B,
    Op_f32_ne = 0x5C,
    Op_f32_lt = 0x5D,
    Op_f32_gt = 0x5E,
    Op_f32_le = 0x5F,
    Op_f32_ge = 0x60,
    Op_f64_eq = 0x61,
    Op_f64_ne = 0x62,
    Op_f64_lt = 0x63,
    Op_f64_gt = 0x64,
    Op_f64_le = 0x65,
    Op_f64_ge = 0x66,
    Op_i32_clz = 0x67,
    Op_i32_ctz = 0x68,
    Op_i32_popcnt = 0x69,
    Op_i32_add = 0x6A,
    Op_i32_sub = 0x6B,
    Op_i32_mul = 0x6C,
    Op_i32_div_s = 0x6D,
    Op_i32_div_u = 0x6E,
    Op_i32_rem_s = 0x6F,
    Op_i32_rem_u = 0x70,
    Op_i32_and = 0x71,
    Op_i32_or = 0x72,
    Op_i32_xor = 0x73,
    Op_i32_shl = 0x74,
    Op_i32_shr_s = 0x75,
    Op_i32_shr_u = 0x76,
    Op_i32_rotl = 0x77,
    Op_i32_rotr = 0x78,
    Op_i64_clz = 0x79,
    Op_i64_ctz = 0x7A,
    Op_i64_popcnt = 0x7B,
    Op_i64_add = 0x7C,
    Op_i64_sub = 0x7D,
    Op_i64_mul = 0x7E,
    Op_i64_div_s = 0x7F,
    Op_i64_div_u = 0x80,
    Op_i64_rem_s = 0x81,
    Op_i64_rem_u = 0x82,
    Op_i64_and = 0x83,
    Op_i64_or = 0x84,
    Op_i64_xor = 0x85,
    Op_i64_shl = 0x86,
    Op_i64_shr_s = 0x87,
    Op_i64_shr_u = 0x88,
    Op_i64_rotl = 0x89,
    Op_i64_rotr = 0x8A,
    Op_f32_abs = 0x8B,
    Op_f32_neg = 0x8C,
    Op_f32_ceil = 0x8D,
    Op_f32_floor = 0x8E,
    Op_f32_trunc = 0x8F,
    Op_f32_nearest = 0x90,
    Op_f32_sqrt = 0x91,
    Op_f32_add = 0x92,
    Op_f32_sub = 0x93,
    Op_f32_mul = 0x94,
    Op_f32_div = 0x95,
    Op_f32_min = 0x96,
    Op_f32_max = 0x97,
    Op_f32_copysign = 0x98,
    Op_f64_abs = 0x99,
    Op_f64_neg = 0x9A,
    Op_f64_ceil = 0x9B,
    Op_f64_floor = 0x9C,
    Op_f64_trunc = 0x9D,
    Op_f64_nearest = 0x9E,
    Op_f64_sqrt = 0x9F,
    Op_f64_add = 0xA0,
    Op_f64_sub = 0xA1,
    Op_f64_mul = 0xA2,
    Op_f64_div = 0xA3,
    Op_f64_min = 0xA4,
    Op_f64_max = 0xA5,
    Op_f64_copysign = 0xA6,
    Op_i32_wrap_i64 = 0xA7,
    Op_i32_trunc_f32_s = 0xA8,
    Op_i32_trunc_f32_u = 0xA9,
    Op_i32_trunc_f64_s = 0xAA,
    Op_i32_trunc_f64_u = 0xAB,
    Op_i64_extend_i32_s = 0xAC,
    Op_i64_extend_i32_u = 0xAD,
    Op_i64_trunc_f32_s = 0xAE,
    Op_i64_trunc_f32_u = 0xAF,
    Op_i64_trunc_f64_s = 0xB0,
    Op_i64_trunc_f64_u = 0xB1,
    Op_f32_convert_i32_s = 0xB2,
    Op_f32_convert_i32_u = 0xB3,
    Op_f32_convert_i64_s = 0xB4,
    Op_f32_convert_i64_u = 0xB5,
    Op_f32_demote_f64 = 0xB6,
    Op_f64_convert_i32_s = 0xB7,
    Op_f64_convert_i32_u = 0xB8,
    Op_f64_convert_i64_s = 0xB9,
    Op_f64_convert_i64_u = 0xBA,
    Op_f64_promote_f32 = 0xBB,
    Op_i32_reinterpret_f32 = 0xBC,
    Op_i64_reinterpret_f64 = 0xBD,
    Op_f32_reinterpret_i32 = 0xBE,
    Op_f64_reinterpret_i64 = 0xBF,
    Op_i32_extend8_s = 0xC0,
    Op_i32_extend16_s = 0xC1,
    Op_i64_extend8_s = 0xC2,
    Op_i64_extend16_s = 0xC3,
    Op_i64_extend32_s = 0xC4,

    Op_prefixed = 0xFC,
};

enum PrefixedOp {
    PrefixedOp_i32_trunc_sat_f32_s = 0x00,
    PrefixedOp_i32_trunc_sat_f32_u = 0x01,
    PrefixedOp_i32_trunc_sat_f64_s = 0x02,
    PrefixedOp_i32_trunc_sat_f64_u = 0x03,
    PrefixedOp_i64_trunc_sat_f32_s = 0x04,
    PrefixedOp_i64_trunc_sat_f32_u = 0x05,
    PrefixedOp_i64_trunc_sat_f64_s = 0x06,
    PrefixedOp_i64_trunc_sat_f64_u = 0x07,
    PrefixedOp_memory_init = 0x08,
    PrefixedOp_data_drop = 0x09,
    PrefixedOp_memory_copy = 0x0A,
    PrefixedOp_memory_fill = 0x0B,
    PrefixedOp_table_init = 0x0C,
    PrefixedOp_elem_drop = 0x0D,
    PrefixedOp_table_copy = 0x0E,
    PrefixedOp_table_grow = 0x0F,
    PrefixedOp_table_size = 0x10,
    PrefixedOp_table_fill = 0x11,
};

static const uint32_t wasm_page_size = 64 * 1024;

struct ProgramCounter {
    uint32_t opcode;
    uint32_t operand;
};

struct TypeInfo {
    uint32_t param_count;
    uint32_t result_count;
};

struct Function {
    // Index to start of code in opcodes/operands.
    struct ProgramCounter pc;
    uint32_t locals_count;
    struct TypeInfo type_info;
};

struct Import {
    struct ByteSlice sym_name;
    struct ByteSlice mod_name;
    struct TypeInfo type_info;
};

struct VirtualMachine {
    uint64_t *stack;
    /// Points to one after the last stack item.
    uint32_t stack_top;
    struct ProgramCounter pc;
    uint32_t memory_len;
    const char *mod_ptr;
    uint8_t *opcodes;
    uint32_t *operands;
    struct Function *functions;
    /// Type index to start of type in module_bytes.
    struct TypeInfo *types;
    uint64_t *globals;
    char *memory;
    struct Import *imports;
    uint32_t imports_len;
    char **args;
    uint32_t *table;
};

struct Label {
    enum Op kind;
    uint32_t stack_depth;
    struct TypeInfo type_info;
    // this is a UINT32_MAX terminated linked list that is stored in the operands array
    uint32_t ref_list;
    union {
        struct ProgramCounter loop_pc;
        uint32_t else_ref;
    } extra;
};

uint64_t offset_counts[2];
uint64_t max_offset = 0;

struct Label labels[500];
uint64_t max_label_depth = 0;

static uint32_t Label_operandCount(const struct Label *label) {
    if (label->kind == Op_loop) {
        return label->type_info.param_count;
    } else {
        return label->type_info.result_count;
    }
}

static void vm_decodeCode(struct VirtualMachine *vm, struct Function *func, uint32_t *code_i,
    struct ProgramCounter *pc)
{
    const char *mod_ptr = vm->mod_ptr;
    uint8_t *opcodes = vm->opcodes;
    uint32_t *operands = vm->operands;
    uint32_t stack_depth = func->type_info.param_count + func->locals_count + 2;
    uint32_t label_i = 0;
    labels[label_i].kind = Op_block;
    labels[label_i].stack_depth = stack_depth;
    labels[label_i].type_info = func->type_info;
    labels[label_i].ref_list = UINT32_MAX;

    for (;;) {
        enum Op opcode = mod_ptr[*code_i];
        *code_i += 1;

        uint32_t initial_stack_depth = stack_depth;
        enum PrefixedOp prefixed_opcode;
        switch (opcode) {
            case Op_unreachable:
            case Op_nop:
            case Op_block:
            case Op_loop:
            case Op_else:
            case Op_end:
            case Op_br:
            case Op_call:
            case Op_return:
            break;

            case Op_if:
            case Op_br_if:
            case Op_br_table:
            case Op_call_indirect:
            case Op_drop:
            case Op_local_set:
            case Op_global_set:
            stack_depth -= 1;
            break;

            case Op_select:
            stack_depth -= 2;
            break;

            case Op_local_get:
            case Op_global_get:
            case Op_memory_size:
            case Op_i32_const:
            case Op_i64_const:
            case Op_f32_const:
            case Op_f64_const:
            stack_depth += 1;
            break;

            case Op_local_tee:
            case Op_i32_load:
            case Op_i64_load:
            case Op_f32_load:
            case Op_f64_load:
            case Op_i32_load8_s:
            case Op_i32_load8_u:
            case Op_i32_load16_s:
            case Op_i32_load16_u:
            case Op_i64_load8_s:
            case Op_i64_load8_u:
            case Op_i64_load16_s:
            case Op_i64_load16_u:
            case Op_i64_load32_s:
            case Op_i64_load32_u:
            case Op_memory_grow:
            case Op_i32_eqz:
            case Op_i32_clz:
            case Op_i32_ctz:
            case Op_i32_popcnt:
            case Op_i64_eqz:
            case Op_i64_clz:
            case Op_i64_ctz:
            case Op_i64_popcnt:
            case Op_f32_abs:
            case Op_f32_neg:
            case Op_f32_ceil:
            case Op_f32_floor:
            case Op_f32_trunc:
            case Op_f32_nearest:
            case Op_f32_sqrt:
            case Op_f64_abs:
            case Op_f64_neg:
            case Op_f64_ceil:
            case Op_f64_floor:
            case Op_f64_trunc:
            case Op_f64_nearest:
            case Op_f64_sqrt:
            case Op_i32_wrap_i64:
            case Op_i32_trunc_f32_s:
            case Op_i32_trunc_f32_u:
            case Op_i32_trunc_f64_s:
            case Op_i32_trunc_f64_u:
            case Op_i64_extend_i32_s:
            case Op_i64_extend_i32_u:
            case Op_i64_trunc_f32_s:
            case Op_i64_trunc_f32_u:
            case Op_i64_trunc_f64_s:
            case Op_i64_trunc_f64_u:
            case Op_f32_convert_i32_s:
            case Op_f32_convert_i32_u:
            case Op_f32_convert_i64_s:
            case Op_f32_convert_i64_u:
            case Op_f32_demote_f64:
            case Op_f64_convert_i32_s:
            case Op_f64_convert_i32_u:
            case Op_f64_convert_i64_s:
            case Op_f64_convert_i64_u:
            case Op_f64_promote_f32:
            case Op_i32_reinterpret_f32:
            case Op_i64_reinterpret_f64:
            case Op_f32_reinterpret_i32:
            case Op_f64_reinterpret_i64:
            case Op_i32_extend8_s:
            case Op_i32_extend16_s:
            case Op_i64_extend8_s:
            case Op_i64_extend16_s:
            case Op_i64_extend32_s:
            break;

            case Op_i32_store:
            case Op_i64_store:
            case Op_f32_store:
            case Op_f64_store:
            case Op_i32_store8:
            case Op_i32_store16:
            case Op_i64_store8:
            case Op_i64_store16:
            case Op_i64_store32:
            stack_depth -= 2;
            break;

            case Op_i32_eq:
            case Op_i32_ne:
            case Op_i32_lt_s:
            case Op_i32_lt_u:
            case Op_i32_gt_s:
            case Op_i32_gt_u:
            case Op_i32_le_s:
            case Op_i32_le_u:
            case Op_i32_ge_s:
            case Op_i32_ge_u:
            case Op_i64_eq:
            case Op_i64_ne:
            case Op_i64_lt_s:
            case Op_i64_lt_u:
            case Op_i64_gt_s:
            case Op_i64_gt_u:
            case Op_i64_le_s:
            case Op_i64_le_u:
            case Op_i64_ge_s:
            case Op_i64_ge_u:
            case Op_f32_eq:
            case Op_f32_ne:
            case Op_f32_lt:
            case Op_f32_gt:
            case Op_f32_le:
            case Op_f32_ge:
            case Op_f64_eq:
            case Op_f64_ne:
            case Op_f64_lt:
            case Op_f64_gt:
            case Op_f64_le:
            case Op_f64_ge:
            case Op_i32_add:
            case Op_i32_sub:
            case Op_i32_mul:
            case Op_i32_div_s:
            case Op_i32_div_u:
            case Op_i32_rem_s:
            case Op_i32_rem_u:
            case Op_i32_and:
            case Op_i32_or:
            case Op_i32_xor:
            case Op_i32_shl:
            case Op_i32_shr_s:
            case Op_i32_shr_u:
            case Op_i32_rotl:
            case Op_i32_rotr:
            case Op_i64_add:
            case Op_i64_sub:
            case Op_i64_mul:
            case Op_i64_div_s:
            case Op_i64_div_u:
            case Op_i64_rem_s:
            case Op_i64_rem_u:
            case Op_i64_and:
            case Op_i64_or:
            case Op_i64_xor:
            case Op_i64_shl:
            case Op_i64_shr_s:
            case Op_i64_shr_u:
            case Op_i64_rotl:
            case Op_i64_rotr:
            case Op_f32_add:
            case Op_f32_sub:
            case Op_f32_mul:
            case Op_f32_div:
            case Op_f32_min:
            case Op_f32_max:
            case Op_f32_copysign:
            case Op_f64_add:
            case Op_f64_sub:
            case Op_f64_mul:
            case Op_f64_div:
            case Op_f64_min:
            case Op_f64_max:
            case Op_f64_copysign:
            stack_depth -= 1;
            break;

            case Op_prefixed:
            prefixed_opcode = read32_uleb128(mod_ptr, code_i);
            switch (prefixed_opcode) {
                case PrefixedOp_i32_trunc_sat_f32_s:
                case PrefixedOp_i32_trunc_sat_f32_u:
                case PrefixedOp_i32_trunc_sat_f64_s:
                case PrefixedOp_i32_trunc_sat_f64_u:
                case PrefixedOp_i64_trunc_sat_f32_s:
                case PrefixedOp_i64_trunc_sat_f32_u:
                case PrefixedOp_i64_trunc_sat_f64_s:
                case PrefixedOp_i64_trunc_sat_f64_u:
                break;

                case PrefixedOp_memory_init:
                case PrefixedOp_memory_copy:
                case PrefixedOp_memory_fill:
                case PrefixedOp_table_init:
                case PrefixedOp_table_copy:
                case PrefixedOp_table_fill:
                stack_depth -= 3;
                break;

                case PrefixedOp_data_drop:
                case PrefixedOp_elem_drop:
                break;

                case PrefixedOp_table_grow:
                stack_depth -= 1;
                break;

                case PrefixedOp_table_size:
                stack_depth += 1;
                break;
            }
        }

        switch (opcode) {
            case Op_block:
            case Op_loop:
            case Op_if:
            {
                label_i += 1;
                max_label_depth = (label_i > max_label_depth) ? label_i : max_label_depth;
                struct Label *label = &labels[label_i];
                int64_t block_type = read64_ileb128(mod_ptr, code_i);
                struct TypeInfo type_info;
                if (block_type < 0) {
                    type_info.param_count = 0;
                    type_info.result_count = block_type != -0x40;
                } else {
                    type_info = vm->types[block_type];
                }
                label->kind = opcode;
                label->stack_depth = stack_depth - type_info.param_count;
                label->type_info = type_info;
                label->ref_list = UINT32_MAX;
                switch (opcode) {
                    case Op_loop:
                    label->extra.loop_pc = *pc;
                    break;

                    case Op_if:
                    opcodes[pc->opcode] = Op_i32_eqz;
                    opcodes[pc->opcode + 1] = Op_br_if;
                    pc->opcode += 2;
                    operands[pc->operand] = type_info.param_count;
                    label->extra.else_ref = pc->operand + 1;
                    pc->operand += 3;
                    break;

                    default:
                    break;
                }
            }
            break;

            case Op_else:
            {
                struct Label * label = &labels[label_i];
                assert(label->kind == Op_if);
                label->kind = opcode;
                uint32_t operand_count = Label_operandCount(label);
                opcodes[pc->opcode] = Op_br;
                pc->opcode += 1;
                operands[pc->operand] = operand_count |
                    (stack_depth - operand_count - label->stack_depth) << 1;
                operands[pc->operand + 1] = label->ref_list;
                label->ref_list = pc->operand + 1;
                pc->operand += 3;
                operands[label->extra.else_ref] = pc->opcode;
                operands[label->extra.else_ref + 1] = pc->operand;
                assert(stack_depth > UINT32_MAX / 4 ||
                    stack_depth - label->type_info.result_count == label->stack_depth);
                stack_depth = label->stack_depth + label->type_info.param_count;
            };
            break;

            case Op_end:
            {
                struct Label * label = &labels[label_i];
                struct ProgramCounter *target_pc = (label->kind == Op_loop) ? &label->extra.loop_pc : pc;
                if (label->kind == Op_if) {
                    operands[label->extra.else_ref] = target_pc->opcode;
                    operands[label->extra.else_ref + 1] = target_pc->operand;
                }
                uint32_t ref = label->ref_list;
                while (ref != UINT32_MAX) {
                    uint32_t next_ref = operands[ref];
                    operands[ref] = target_pc->opcode;
                    operands[ref + 1] = target_pc->operand;
                    ref = next_ref;
                }
                uint32_t result_stack_depth = label->stack_depth + label->type_info.result_count;
                assert((stack_depth > UINT32_MAX / 4) || (stack_depth == result_stack_depth));
                stack_depth = result_stack_depth;
                if (label_i == 0) {
                    opcodes[pc->opcode] = Op_return;
                    pc->opcode += 1;
                    uint32_t operand_count = Label_operandCount(&labels[0]);
                    operands[pc->operand] = operand_count | (2 + operand_count) << 1;
                    stack_depth -= operand_count;
                    assert(stack_depth == labels[0].stack_depth);
                    operands[pc->operand + 1] = stack_depth;
                    pc->operand += 2;
                    return;
                }
                label_i -= 1;
            }
            break;

            case Op_br:
            case Op_br_if:
            {
                uint32_t label_idx = read32_uleb128(mod_ptr, code_i);
                struct Label * label = &labels[label_i - label_idx];
                uint32_t operand_count = Label_operandCount(label);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = operand_count |
                    (stack_depth - operand_count - label->stack_depth) << 1;
                operands[pc->operand + 1] = label->ref_list;
                label->ref_list = pc->operand + 1;
                pc->operand += 3;
            }
            break;

            case Op_br_table:
            {
                uint32_t labels_len = read32_uleb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = labels_len;
                pc->operand += 1;
                for (uint32_t i = 0; i <= labels_len; i += 1) {
                    uint32_t label_idx = read32_uleb128(mod_ptr, code_i);
                    struct Label * label = &labels[label_i - label_idx];
                    uint32_t operand_count = Label_operandCount(label);
                    operands[pc->operand] = operand_count |
                        (stack_depth - operand_count - label->stack_depth) << 1;
                    operands[pc->operand + 1] = label->ref_list;
                    label->ref_list = pc->operand + 1;
                    pc->operand += 3;
                }
            }
            break;

            case Op_call:
            {
                uint32_t fn_id = read32_uleb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = fn_id;
                pc->operand += 1;
                struct TypeInfo type_info = (fn_id < vm->imports_len) ?
                    vm->imports[fn_id].type_info :
                    vm->functions[fn_id - vm->imports_len].type_info;
                stack_depth = stack_depth - type_info.param_count + type_info.result_count;
            }
            break;

            case Op_call_indirect:
            {
                uint32_t type_idx = read32_uleb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                if (read32_uleb128(mod_ptr, code_i) != 0) panic("expected zero");
                struct TypeInfo info = vm->types[type_idx];
                stack_depth = stack_depth - info.param_count + info.result_count;
            }
            break;

            case Op_return:
            {
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                uint32_t operand_count = Label_operandCount(&labels[0]);
                operands[pc->operand] = operand_count |
                    (2 + stack_depth - labels[0].stack_depth) << 1;
                stack_depth -= operand_count;
                operands[pc->operand + 1] = stack_depth;
                pc->operand += 2;
            }
            break;

            case Op_local_get:
            case Op_local_set:
            case Op_local_tee:
            {
                uint32_t local_idx = read32_uleb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = initial_stack_depth - local_idx;
                pc->operand += 1;
            }
            break;

            case Op_global_get:
            case Op_global_set:
            {
                uint32_t global_idx = read32_uleb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = global_idx;
                pc->operand += 1;
            }
            break;

            case Op_i32_load:
            case Op_i64_load:
            case Op_f32_load:
            case Op_f64_load:
            case Op_i32_load8_s:
            case Op_i32_load8_u:
            case Op_i32_load16_s:
            case Op_i32_load16_u:
            case Op_i64_load8_s:
            case Op_i64_load8_u:
            case Op_i64_load16_s:
            case Op_i64_load16_u:
            case Op_i64_load32_s:
            case Op_i64_load32_u:
            case Op_i32_store:
            case Op_i64_store:
            case Op_f32_store:
            case Op_f64_store:
            case Op_i32_store8:
            case Op_i32_store16:
            case Op_i64_store8:
            case Op_i64_store16:
            case Op_i64_store32:
            {
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                read32_uleb128(mod_ptr, code_i);
                operands[pc->operand] = read32_uleb128(mod_ptr, code_i);
                offset_counts[operands[pc->operand] != 0] += 1;
                max_offset = (operands[pc->operand] > max_offset) ?
                    operands[pc->operand] : max_offset;
                pc->operand += 1;
            }
            break;

            case Op_memory_size:
            case Op_memory_grow:
            {
                assert(mod_ptr[*code_i] == 0);
                *code_i += 1;
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
            }
            break;

            case Op_i32_const:
            {
                uint32_t x = read32_ileb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = x;
                pc->operand += 1;
            }
            break;

            case Op_i64_const:
            {
                uint64_t x = read64_ileb128(mod_ptr, code_i);
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = x & UINT32_MAX;
                operands[pc->operand + 1] = (x >> 32) & UINT32_MAX;
                pc->operand += 2;
            }
            break;

            case Op_f32_const:
            {
                uint32_t x;
                memcpy(&x, mod_ptr + *code_i, 4);
                *code_i += 4;
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = x;
                pc->operand += 1;
            }
            break;

            case Op_f64_const:
            {
                uint64_t x;
                memcpy(&x, mod_ptr + *code_i, 8);
                *code_i += 8;
                opcodes[pc->opcode] = opcode;
                pc->opcode += 1;
                operands[pc->operand] = x & UINT32_MAX;
                operands[pc->operand + 1] = (x >> 32) & UINT32_MAX;
                pc->operand += 2;
            }
            break;

            case Op_prefixed:
            switch (prefixed_opcode) {
                case PrefixedOp_i32_trunc_sat_f32_s:
                case PrefixedOp_i32_trunc_sat_f32_u:
                case PrefixedOp_i32_trunc_sat_f64_s:
                case PrefixedOp_i32_trunc_sat_f64_u:
                case PrefixedOp_i64_trunc_sat_f32_s:
                case PrefixedOp_i64_trunc_sat_f32_u:
                case PrefixedOp_i64_trunc_sat_f64_s:
                case PrefixedOp_i64_trunc_sat_f64_u:
                opcodes[pc->opcode] = opcode;
                opcodes[pc->opcode + 1] = prefixed_opcode;
                pc->opcode += 2;
                break;

                case PrefixedOp_memory_copy:
                assert(mod_ptr[*code_i] == 0 && mod_ptr[*code_i + 1] == 0);
                *code_i += 2;
                opcodes[pc->opcode] = opcode;
                opcodes[pc->opcode + 1] = prefixed_opcode;
                pc->opcode += 2;
                break;

                case PrefixedOp_memory_fill:
                assert(mod_ptr[*code_i] == 0);
                *code_i += 1;
                opcodes[pc->opcode] = opcode;
                opcodes[pc->opcode + 1] = prefixed_opcode;
                pc->opcode += 2;
                break;

                default: panic("unreachable");
            }
            break;

            default:
            opcodes[pc->opcode] = opcode;
            pc->opcode += 1;
            break;
        }

        switch (opcode) {
            case Op_unreachable:
            case Op_return:
            case Op_br:
            case Op_br_table:
            stack_depth = UINT32_MAX / 2;
            break;

            default:
            break;
        }
    }
}


int main(int argc, char **argv) {
    char *memory = mmap( NULL, max_memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    const char *zig_lib_dir_path = argv[1];
    const char *zig_cache_dir_path = argv[2];
    const size_t vm_argv_start = 3;
    const char *wasm_file = argv[vm_argv_start];

    const struct ByteSlice mod = read_file_alloc(wasm_file);

    int cwd = err_wrap("opening cwd", open(".", O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_PATH));
    mkdir(zig_cache_dir_path, 0666);
    int cache_dir = err_wrap("opening cache dir", open(zig_cache_dir_path, O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_PATH));
    int zig_lib_dir = err_wrap("opening zig lib dir", open(zig_lib_dir_path, O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_PATH));

    add_preopen(0, "stdin", STDIN_FILENO);
    add_preopen(1, "stdout", STDOUT_FILENO);
    add_preopen(2, "stderr", STDERR_FILENO);
    add_preopen(3, ".", cwd);
    add_preopen(4, "/cache", cache_dir);
    add_preopen(5, "/lib", zig_lib_dir);

    uint32_t i = 0;

    if (mod.ptr[0] != 0 || mod.ptr[1] != 'a' || mod.ptr[2] != 's' || mod.ptr[3] != 'm') {
        panic("bad magic");
    }
    i += 4;

    uint32_t version = read32le(mod.ptr + i);
    i += 4;
    if (version != 1) panic("bad wasm version");

    uint32_t section_starts[13];
    memset(&section_starts, 0, 4 * 13);

    while (i < mod.len) {
        uint8_t section_id = mod.ptr[i];
        i += 1;
        uint32_t section_len = read32_uleb128(mod.ptr, &i);
        section_starts[section_id] = i;
        i += section_len;
    }

    // Map type indexes to offsets into the module.
    struct TypeInfo *types;
    {
        i = section_starts[Section_type];
        uint32_t types_len = read32_uleb128(mod.ptr, &i);
        types = arena_alloc(sizeof(struct TypeInfo) * types_len);
        for (size_t type_i = 0; type_i < types_len; type_i += 1) {
            struct TypeInfo *info = &types[type_i];
            if (mod.ptr[i] != 0x60) panic("bad type byte");
            i += 1;
            info->param_count = read32_uleb128(mod.ptr, &i);
            for (uint32_t param_i = 0; param_i < info->param_count; param_i += 1) {
                read32_ileb128(mod.ptr, &i);
            }
            info->result_count = read32_uleb128(mod.ptr, &i);
            for (uint32_t result_i = 0; result_i < info->result_count; result_i += 1) {
                read32_ileb128(mod.ptr, &i);
            }
        }
    }

    // Count the imported functions so we can correct function references.
    struct Import *imports;
    uint32_t imports_len;
    {
        i = section_starts[Section_import];
        imports_len = read32_uleb128(mod.ptr, &i);
        imports = arena_alloc(sizeof(struct Import) * imports_len);
        for (size_t imp_i = 0; imp_i < imports_len; imp_i += 1) {
            struct Import *imp = &imports[imp_i];
            imp->mod_name = read_name(mod.ptr, &i);
            imp->sym_name = read_name(mod.ptr, &i);
            uint32_t desc = read32_uleb128(mod.ptr, &i);
            if (desc != 0) panic("external kind not function");
            imp->type_info = types[read32_uleb128(mod.ptr, &i)];
        }
    }

    // Find _start in the exports
    uint32_t start_fn_idx;
    {
        i = section_starts[Section_export];
        uint32_t count = read32_uleb128(mod.ptr, &i);
        for (; count > 0; count -= 1) {
            struct ByteSlice name = read_name(mod.ptr, &i);
            uint32_t desc = read32_uleb128(mod.ptr, &i);
            start_fn_idx = read32_uleb128(mod.ptr, &i);
            if (desc == 0 && name.len == strlen("_start") &&
                memcmp(name.ptr, "_start", name.len) == 0)
            {
                break;
            }
        }
        if (count == 0) panic("_start symbol not found");
    }

    // Map function indexes to offsets into the module and type index.
    struct Function *functions;
    uint32_t functions_len;
    {
        i = section_starts[Section_function];
        functions_len = read32_uleb128(mod.ptr, &i);
        functions = arena_alloc(sizeof(struct Function) * functions_len);
        for (size_t func_i = 0; func_i < functions_len; func_i += 1) {
            struct Function *func = &functions[func_i];
            func->type_info = types[read32_uleb128(mod.ptr, &i)];
        }
    }

    // Allocate and initialize globals.
    uint64_t *globals;
    {
        i = section_starts[Section_global];
        uint32_t globals_len = read32_uleb128(mod.ptr, &i);
        globals = arena_alloc(sizeof(uint64_t) * globals_len);
        for (size_t glob_i = 0; glob_i < globals_len; glob_i += 1) {
            uint64_t *global = &globals[glob_i];
            uint32_t content_type = read32_uleb128(mod.ptr, &i);
            uint32_t mutability = read32_uleb128(mod.ptr, &i);
            if (mutability != 1) panic("expected mutable global");
            if (content_type != 0x7f) panic("unexpected content type");
            uint8_t opcode = mod.ptr[i];
            i += 1;
            if (opcode != Op_i32_const) panic("expected i32_const op");
            uint32_t init = read32_ileb128(mod.ptr, &i);
            *global = (uint32_t)init;
        }
    }

    // Allocate and initialize memory.
    uint32_t memory_len;
    {
        i = section_starts[Section_memory];
        uint32_t memories_len = read32_uleb128(mod.ptr, &i);
        if (memories_len != 1) panic("unexpected memory count");
        uint32_t flags = read32_uleb128(mod.ptr, &i);
        memory_len = read32_uleb128(mod.ptr, &i) * wasm_page_size;

        i = section_starts[Section_data];
        uint32_t datas_count = read32_uleb128(mod.ptr, &i);
        for (; datas_count > 0; datas_count -= 1) {
            uint32_t mode = read32_uleb128(mod.ptr, &i);
            if (mode != 0) panic("expected mode 0");
            enum Op opcode = mod.ptr[i];
            i += 1;
            if (opcode != Op_i32_const) panic("expected opcode i32_const");
            uint32_t offset = read32_uleb128(mod.ptr, &i);
            enum Op end = mod.ptr[i];
            if (end != Op_end) panic("expected end opcode");
            i += 1;
            uint32_t bytes_len = read32_uleb128(mod.ptr, &i);
            memcpy(memory + offset, mod.ptr + i, bytes_len);
            i += bytes_len;
        }
    }

    uint32_t *table = NULL;
    {
        i = section_starts[Section_table];
        uint32_t table_count = read32_uleb128(mod.ptr, &i);
        if (table_count > 1) {
            panic("expected only one table section");
        } else if (table_count == 1) {
            uint32_t element_type = read32_uleb128(mod.ptr, &i);
            uint32_t has_max = read32_uleb128(mod.ptr, &i);
            if (has_max != 1) panic("expected has_max==1");
            uint32_t initial = read32_uleb128(mod.ptr, &i);
            uint32_t maximum = read32_uleb128(mod.ptr, &i);

            i = section_starts[Section_element];
            uint32_t element_section_count = read32_uleb128(mod.ptr, &i);
            if (element_section_count != 1) panic("expected one element section");
            uint32_t flags = read32_uleb128(mod.ptr, &i);
            enum Op opcode = mod.ptr[i];
            i += 1;
            if (opcode != Op_i32_const) panic("expected op i32_const");
            uint32_t offset = read32_uleb128(mod.ptr, &i);
            enum Op end = mod.ptr[i];
            if (end != Op_end) panic("expected op end");
            i += 1;
            uint32_t elem_count = read32_uleb128(mod.ptr, &i);

            table = arena_alloc(sizeof(uint32_t) * maximum);
            memset(table, 0, maximum);

            for (uint32_t elem_i = 0; elem_i < elem_count; elem_i += 1) {
                table[elem_i + offset] = read32_uleb128(mod.ptr, &i);
            }
        }
    }

    struct VirtualMachine vm;
    vm.stack = arena_alloc(sizeof(uint64_t) * 10000000),
    vm.mod_ptr = mod.ptr;
    vm.opcodes = arena_alloc(2000000);
    vm.operands = arena_alloc(sizeof(uint32_t) * 2000000);
    vm.stack_top = 0;
    vm.functions = functions;
    vm.types = types;
    vm.globals = globals;
    vm.memory = memory;
    vm.memory_len = memory_len;
    vm.imports = imports;
    vm.imports_len = imports_len;
    vm.args = argv + vm_argv_start;
    vm.table = table;

    {
        uint32_t code_i = section_starts[Section_code];
        uint32_t codes_len = read32_uleb128(mod.ptr, &code_i);
        if (codes_len != functions_len) panic("code/function length mismatch");
        struct ProgramCounter pc;
        pc.opcode = 0;
        pc.operand = 0;
        for (uint32_t func_i = 0; func_i < functions_len; func_i += 1) {
            struct Function *func = &functions[func_i];
            uint32_t size = read32_uleb128(mod.ptr, &code_i);
            uint32_t code_begin = code_i;

            func->locals_count = 0;
            uint32_t local_sets_count = read32_uleb128(mod.ptr, &code_i);
            for (; local_sets_count > 0; local_sets_count -= 1) {
                uint32_t current_count = read32_uleb128(mod.ptr, &code_i);
                uint32_t local_type = read32_uleb128(mod.ptr, &code_i);
                func->locals_count += current_count;
            }

            func->pc = pc;
            vm_decodeCode(&vm, func, &code_i, &pc);
            if (code_i != code_begin + size) panic("bad code size");
        }

        uint64_t opcode_counts[0x100];
        memset(opcode_counts, 0, 0x100);
        uint64_t prefixed_opcode_counts[0x100];
        memset(prefixed_opcode_counts, 0, 0x100);
        bool is_prefixed = false;
        for (uint32_t opcode_i = 0; opcode_i < pc.opcode; opcode_i += 1) {
            uint8_t opcode = vm.opcodes[opcode_i];
            if (!is_prefixed) {
                opcode_counts[opcode] += 1;
                is_prefixed = opcode == Op_prefixed;
            } else {
                prefixed_opcode_counts[opcode] += 1;
                is_prefixed = false;
            }
        }
    }

    panic("TODO: finish porting the rest");

    return 0;
}


