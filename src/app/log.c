/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2015 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include "bson/bson.h"
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "symbol.h"
#include "utf8.h"

// Maximum length of a buffer so we try to avoid polluting logs with garbage.
#define BUFFER_LOG_MAX 4096
#define EXCEPTION_MAXCOUNT 1024

static CRITICAL_SECTION g_mutex;
static uint32_t g_starttick;
static uint8_t *g_api_init;

static wchar_t g_log_pipename[MAX_PATH];
static HANDLE g_log_handle;

#if DEBUG
static wchar_t g_debug_filepath[MAX_PATH];
static HANDLE g_debug_handle;
#endif

static void log_raw(const char *buf, size_t length);

static int open_handles(uint32_t pid)
{
    printf("open_handles called\n");
    do {
        // TODO Use NtCreateFile instead of CreateFileW.
        g_log_handle = CreateFileW(g_log_pipename, GENERIC_WRITE,
            FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH, NULL);

        sleep(1);
    } while (g_log_handle == INVALID_HANDLE_VALUE);

    printf("g_log_handle ok !\n");

    // The process identifier.
    uint32_t process_identifier = pid;
    log_raw((const char *) &process_identifier, sizeof(process_identifier));

#if DEBUG
    g_debug_handle = CreateFileW(g_debug_filepath,
        GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif
    return 0;
}

static void log_raw(const char *buf, size_t length)
{
    EnterCriticalSection(&g_mutex);

    while (length != 0) {
        uint32_t written = 0; uint32_t status;

        status = write_file(g_log_handle, buf, length, &written);
        /*if(NT_SUCCESS(status) == FALSE) {
            // It is possible that malware closes our pipe handle. In that
            // case we'll get an invalid handle error. Let's just open a new
            // pipe handle.
            if(status == STATUS_INVALID_HANDLE) {
                if(open_handles() < 0) {
                    break;
                }
            }
            else {
                pipe("CRITICAL:Handle case where the log handle is closed "
                    "(last error 0x%x).", status);
                break;
            }
        }*/

        length -= written, buf += written;
    }

    LeaveCriticalSection(&g_mutex);
}

static void log_int32(bson *b, const char *idx, int value)
{
    bson_append_int(b, idx, value);
}

static void log_int64(bson *b, const char *idx, int64_t value)
{
    bson_append_long(b, idx, value);
}

static void log_intptr(bson *b, const char *idx, intptr_t value)
{
#if __x86_64__
    bson_append_long(b, idx, value);
#else
    bson_append_int(b, idx, value);
#endif
}

static void log_string(bson *b, const char *idx, const char *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    int ret, utf8len;

    char *utf8s = utf8_string(str, length);
    utf8len = *(int *) utf8s;
    ret = bson_append_binary(b, idx, BSON_BIN_BINARY, utf8s+4, utf8len);
    if(ret == BSON_ERROR) {
        pipe("CRITICAL:Error creating bson string, error, %x utf8len %d.",
            b->err, utf8len);
    }
    mem_free(utf8s);
}

void log_wstring(bson *b, const char *idx, const wchar_t *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    int ret, utf8len;
    char *utf8s = utf8_wstring(str, length);
    utf8len = *(int *) utf8s;
    ret = bson_append_binary(b, idx, BSON_BIN_BINARY, utf8s+4, utf8len);
    if(ret == BSON_ERROR) {
        pipe("CRITICAL:Error creating bson wstring, error %x, utf8len %d.",
            b->err, utf8len);
    }
    mem_free(utf8s);
}

static void log_argv(bson *b, const char *idx, int argc, const char **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        ultostr(i, index, 10);
        log_string(b, index, argv[i], -1);
    }
    bson_append_finish_array(b);
}

static void log_wargv(bson *b, const char *idx,
    int argc, const wchar_t **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        ultostr(i, index, 10);
        log_wstring(b, index, argv[i], -1);
    }

    bson_append_finish_array(b);
}

static void log_buffer(bson *b, const char *idx,
    const uint8_t *buf, uintptr_t length)
{
    uintptr_t trunclength = length < BUFFER_LOG_MAX ? length : BUFFER_LOG_MAX;

    if(buf == NULL) {
        trunclength = 0;
    }

    bson_append_binary(b, idx, BSON_BIN_BINARY,
        (const char *) buf, trunclength);
}

void log_explain(uint32_t index, char *format)
{
    bson b; char argidx[4];

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_string(&b, "name", sig_apiname(index));
    bson_append_string(&b, "type", "info");
    bson_append_string(&b, "category", sig_category(index));

    bson_append_start_array(&b, "args");
    bson_append_string(&b, "0", "is_success");
    bson_append_string(&b, "1", "retval");

    const char *fmt = format;

    for (uint32_t argnum = 2; *fmt != 0; argnum++, fmt++) {
        ultostr(argnum, argidx, 10);

        // Ignore buffers, they are sent over separately.
        if(*fmt == '!') {
            argnum--;
            fmt++;
            continue;
        }

        const char *argname = sig_param_name(index, argnum-2);

        // On certain formats, we need to tell cuckoo about them for
        // nicer display / matching.
        if(*fmt == 'p' || *fmt == 'P' || *fmt == 'x') {
            bson_append_start_array(&b, argidx);
            bson_append_string(&b, "0", argname);

            if(*fmt == 'p' || *fmt == 'P') {
                bson_append_string(&b, "1", "p");
            }
            else if(*fmt == 'x') {
                bson_append_string(&b, "1", "x");
            }
            bson_append_finish_array(&b);
        }
        else {
            bson_append_string(&b, argidx, argname);
        }
    }

    bson_append_finish_array(&b);
    bson_append_start_object(&b, "flags_value");


    for (uint32_t idx = 0; sig_flag_name(index, idx) != NULL; idx++) {
        const flag_repr_t *f = flag_value(sig_flag_value(index, idx));
        bson_append_start_array(&b, sig_flag_name(index, idx));

        for (uint32_t idx2 = 0; f->repr != NULL; idx2++, f++) {
            ultostr(idx, argidx, 10);
            bson_append_start_array(&b, argidx);
            bson_append_int(&b, "0", f->value);
            bson_append_string(&b, "1", f->repr);
            bson_append_finish_array(&b);
        }

        bson_append_finish_array(&b);
    }

    bson_append_finish_object(&b);
    bson_append_start_object(&b, "flags_bitmask");

    for (uint32_t idx = 0; sig_flag_name(index, idx) != NULL; idx++) {
        const flag_repr_t *f = flag_bitmask(sig_flag_value(index, idx));
        bson_append_start_array(&b, sig_flag_name(index, idx));

        for (uint32_t idx2 = 0; f->repr != NULL; idx2++, f++) {
            ultostr(idx, argidx, 10);
            bson_append_start_array(&b, argidx);
            bson_append_int(&b, "0", f->value);
            bson_append_string(&b, "1", f->repr);
            bson_append_finish_array(&b);
        }

        bson_append_finish_array(&b);
    }

    bson_append_finish_object(&b);
    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

#if DEBUG

static void _log_stacktrace(bson *b)
{
    uintptr_t addrs[RETADDRCNT], count;
    char number[20], sym[512];

    bson_append_start_array(b, "s");

    count = stacktrace(NULL, addrs, RETADDRCNT);

    for (uint32_t idx = 4; idx < count; idx++) {
        ultostr(idx-4, number, 10);

        symbol((const uint8_t *) addrs[idx], sym, sizeof(sym)-32);
        if(sym[0] != 0) {
            our_snprintf(sym + our_strlen(sym),
                sizeof(sym) - our_strlen(sym), " @ ");
        }

        our_snprintf(sym + our_strlen(sym), sizeof(sym) - our_strlen(sym),
            "%p", (const uint8_t *) addrs[idx]);
        bson_append_string(b, number, sym);
    }

    bson_append_finish_array(b);
}

#endif

void log_api(uint32_t index, int is_success, uintptr_t return_value,
    uint64_t hash, last_error_t *lasterr, char *format, ...)
{
    va_list args; char idx[4];
    va_start(args, format);

    EnterCriticalSection(&g_mutex);

    if(g_api_init[index] == 0) {
        log_explain(index, format);
        g_api_init[index] = 1;
    }

    LeaveCriticalSection(&g_mutex);

    bson b;

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_int(&b, "T", 0);
    bson_append_int(&b, "t", 0);//get_tick_count() - g_starttick);
    bson_append_long(&b, "h", hash);

#if DEBUG
    _log_stacktrace(&b);
#endif

    bson_append_start_array(&b, "args");
    bson_append_int(&b, "0", is_success);
    bson_append_long(&b, "1", return_value);

    int argnum = 2, override = 0;

    for (const char *fmt = format; *fmt != 0; fmt++) {
        ultostr(argnum++, idx, 10);

        // Limitation override. Instead of displaying this right away in the
        // report we turn it into a buffer (much like the dropped files).
        if(*fmt == '!') {
            override = 1;
            argnum--;
            fmt++;
        }

        if(*fmt == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(&b, idx, s, -1);
        }
        else if(*fmt == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "", len = 0;
            log_string(&b, idx, s, len);
        }
        else if(*fmt == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(&b, idx, s, -1);
        }
        else if(*fmt == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"", len = 0;
            log_wstring(&b, idx, s, len);
        }
        else if(*fmt == 'b') {
            uintptr_t len = va_arg(args, uintptr_t);
            const uint8_t *s = va_arg(args, const uint8_t *);
            if(override == 0) {
                log_buffer(&b, idx, s, len);
            }
        }
        else if(*fmt == 'B') {
            uintptr_t *len = va_arg(args, uintptr_t *);
            const uint8_t *s = va_arg(args, const uint8_t *);
            if(override == 0) {
                log_buffer(&b, idx, s, len == NULL ? 0 : *len);
            }
        }
        else if(*fmt == 'i' || *fmt == 'x') {
            int value = va_arg(args, int);
            log_int32(&b, idx, value);
        }
        else if(*fmt == 'I') {
            int *value = va_arg(args, int *);
            log_int32(&b, idx, value != NULL ? *value : 0);
        }
        else if(*fmt == 'l' || *fmt == 'p') {
            uintptr_t value = va_arg(args, uintptr_t);
            log_intptr(&b, idx, value);
        }
        else if(*fmt == 'L' || *fmt == 'P') {
            uintptr_t *ptr = va_arg(args, uintptr_t *);
            log_intptr(&b, idx, ptr != NULL ? *ptr : 0);
        }
        else if(*fmt == 'o') {
            ANSI_STRING *str = va_arg(args, ANSI_STRING *);
            if(str == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_string(&b, idx, str->Buffer, str->Length);
            }
        }
        else if(*fmt == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(&b, idx, argc, argv);
        }
        else if(*fmt == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(&b, idx, argc, argv);
        }
        else if(*fmt == 'r' || *fmt == 'R') {
            uint32_t *type = va_arg(args, uint32_t *);
            uint32_t *size = va_arg(args, uint32_t *);
            uint8_t *data = va_arg(args, uint8_t *);

            uint32_t _type = REG_NONE, _size = 0;

            if(type == NULL) {
                type = &_type;
            }
            if(size == NULL) {
                size = &_size;
            }

            if(*type == REG_NONE) {
                log_string(&b, idx, NULL, 0);
            }
            else if(*type == REG_DWORD || *type == REG_DWORD_LITTLE_ENDIAN) {
                uint32_t value = 0;
                if(data != NULL) {
                    value = *(uint32_t *) data;
                }
                log_int32(&b, idx, value);
            }
            else if(*type == REG_EXPAND_SZ || *type == REG_SZ ||
                    *type == REG_MULTI_SZ) {
                if(*fmt == 'r') {
                    uint32_t length = *size;
                    // Strings tend to be zero-terminated twice, so check for
                    // that and if that's the case, then ignore the trailing
                    // nullbyte.
                    if(data != NULL &&
                            our_strlen((const char *) data) == length - 1) {
                        length--;
                    }
                    log_string(&b, idx, (const char *) data, length);
                }
                else {
                    int32_t length = *size / sizeof(wchar_t);
                    // Strings tend to be zero-terminated twice, so check for
                    // that and if that's the case, then ignore the trailing
                    // nullbyte.
                    if(data != NULL &&
                            lstrlenW((const wchar_t *) data) == length - 1) {
                        length--;
                    }
                    log_wstring(&b, idx, (const wchar_t *) data, length);
                }
            }
            else if(*type == REG_QWORD || *type == REG_QWORD_LITTLE_ENDIAN) {
                uint64_t value = 0;
                if(data != NULL) {
                    value = *(uint64_t *) data;
                }
                log_int64(&b, idx, value);
            }
            else {
                log_buffer(&b, idx, data, *size);
            }
        }
        else if(*fmt == 'q') {
            int64_t value = va_arg(args, int64_t);
            log_int64(&b, idx, value);
        }
        else if(*fmt == 'Q') {
            LARGE_INTEGER *value = va_arg(args, LARGE_INTEGER *);
            log_int64(&b, idx, value != NULL ? value->QuadPart : 0);
        }
        else if(*fmt == 'z') {
            bson *value = va_arg(args, bson *);
            if(value == NULL) {
                bson_append_null(&b, idx);
            }
            else {
                bson_append_bson(&b, idx, value);
            }
        }
        else if(*fmt == 'c') {
            char buf[64];
            REFCLSID rclsid = va_arg(args, REFCLSID);
            clsid_to_string(rclsid, buf);
            log_string(&b, idx, buf, -1);
        }
        else {
            char buf[2] = {*fmt, 0};
            pipe("CRITICAL:Invalid format specifier: %z", buf);
        }

        override = 0;
    }

    va_end(args);

    bson_append_finish_array(&b);
    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

void log_new_process(int pid, char *filename)
{
    FILETIME st;

    g_starttick = GetTickCount();
    GetSystemTimeAsFileTime(&st);

#if __x86_64__
    int is_64bit = 1;
#else
    int is_64bit = 0;
#endif

    printf("%filename : s\n", filename);

    log_api(sig_index_process(), 1, 0, 0, NULL, "iiiisui", st.dwLowDateTime,
            st.dwHighDateTime, pid, parent_process_identifier(pid) , 
            filename, NULL, is_64bit);
}

void log_anomaly(const char *subcategory,
    const char *funcname, const char *msg)
{
    log_api(sig_index_anomaly(), 1, 0, 0, NULL,
        0, subcategory, funcname, msg);
}


static void *_bson_malloc(size_t length)
{
    return mem_alloc(length);
}

static void *_bson_realloc(void *ptr, size_t length)
{
    return mem_realloc(ptr, length);
}

static void _bson_free(void *ptr)
{
    mem_free(ptr);
}

#if DEBUG

void log_debug(const char *fmt, ...)
{
    EnterCriticalSection(&g_mutex);

    static char message[0x1000]; int length; va_list args;

    va_start(args, fmt);
    length = our_vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    write_file(g_debug_handle, message, length, NULL);

    LeaveCriticalSection(&g_mutex);
}

#endif

void log_init(const char *pipe_name, int pid, char *procname)
{
    InitializeCriticalSection(&g_mutex);

    printf("before bson_set_heap_stuff\n");
    bson_set_heap_stuff(&_bson_malloc, &_bson_realloc, &_bson_free);
    g_api_init = virtual_alloc_rw(NULL, sig_count() * sizeof(uint8_t));
    printf("after virtual_alloc_rw\n");

#if DEBUG
    char filepath[MAX_PATH];
    our_snprintf(filepath, MAX_PATH, "C:\\monitor-debug-%d.txt",
        GetCurrentProcessId());
    pipe("FILE_NEW:%z", filepath);
    wcsncpyA(g_debug_filepath, filepath, MAX_PATH);
#endif

    printf("before wcsncpyA\n");
    wcsncpyA(g_log_pipename, pipe_name, MAX_PATH);
    printf("before open_handles\n");
    open_handles(pid);
    printf("after open_handles\n");

    log_raw("BSON\n", 5);
    log_new_process(pid, procname);

    printf("log done\n");
}
