// TODO get rid of _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

static uint32_t read32_uleb128(const char *ptr, ssize_t *i) {
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

static int32_t read32_ileb128(const char *ptr, ssize_t *i) {
    int64_t result = 0;
    uint32_t shift = 0;

    for (;;) {
        uint32_t byte = ptr[*i];
        *i += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if ((byte & 0x40)) {
                uint64_t extend = 0;
                result |= (~extend << shift);
            }
            return result;
        }
        if (shift >= 32) panic("read32_ileb128 failed");
    }
}

static struct ByteSlice read_name(char *ptr, ssize_t *i) {
    uint32_t len = read32_uleb128(ptr, i);
    struct ByteSlice res;
    res.ptr = ptr + *i;
    res.len = len;
    *i += len;
    return res;
}

struct Import {
    struct ByteSlice sym_name;
    struct ByteSlice mod_name;
    uint32_t type_idx;
};

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

    ssize_t i = 0;

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
    {
        i = section_starts[Section_import];
        uint32_t imports_len = read32_uleb128(mod.ptr, &i);
        imports = arena_alloc(sizeof(struct Import) * imports_len);
        for (size_t imp_i = 0; imp_i < imports_len; imp_i += 1) {
            struct Import *imp = &imports[imp_i];
            imp->mod_name = read_name(mod.ptr, &i);
            imp->sym_name = read_name(mod.ptr, &i);
            uint32_t desc = read32_uleb128(mod.ptr, &i);
            if (desc != 0) panic("external kind not function");
            imp->type_idx = read32_uleb128(mod.ptr, &i);
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
    {
        i = section_starts[Section_function];
        uint32_t funcs_len = read32_uleb128(mod.ptr, &i);
        functions = arena_alloc(sizeof(struct Function) * funcs_len);
        for (size_t func_i = 0; func_i < funcs_len; func_i += 1) {
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

    panic("TODO: finish porting the rest");

    return 0;
}


