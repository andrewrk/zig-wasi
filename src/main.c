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

int main(int argc, char **argv) {
    const char *memory = mmap( NULL, max_memory, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);

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

    panic("TODO: finish porting the rest");

    return 0;
}


