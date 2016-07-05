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
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>
#include "bson/bson.h"
#include "hooking.h"
#include "ignore.h"
#include "log.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"
#include "sha1.h"
#include "symbol.h"

static char g_shutdown_mutex[MAX_PATH];
static array_t g_unicode_buffer_ptr_array;
static array_t g_unicode_buffer_use_array;

static uintptr_t g_monitor_start;
static uintptr_t g_monitor_end;

static monitor_hook_t g_hook_library;

#define HKCU_PREFIX  L"\\REGISTRY\\USER\\S-1-5-"
#define HKCU_PREFIX2 L"HKEY_USERS\\S-1-5-"
#define HKLM_PREFIX  L"\\REGISTRY\\MACHINE"

static wchar_t g_aliases[64][2][MAX_PATH];
static uint32_t g_alias_index;

uint32_t g_monitor_track = 1;
uint32_t g_monitor_mode = HOOK_MODE_ALL;

#define ADD_ALIAS(before, after) \
    if(g_alias_index == 64) { \
        pipe("CRITICAL:Too many aliases!"); \
        exit(1); \
    } \
    wcscpy(g_aliases[g_alias_index][0], before); \
    wcscpy(g_aliases[g_alias_index][1], after); \
    g_alias_index++;


uint32_t parent_process_identifier(int pid)
{
    return 0;
}


void wcsncpyA(wchar_t *dst, const char *src, uint32_t length)
{
    while (*src != 0 && length > 1) {
        *dst++ = *src++, length--;
    }
    *dst = 0;
}


void *memdup(const void *addr, uint32_t length)
{
    if(addr != NULL && length != 0) {
        void *ret = mem_alloc(length);
        if(ret != NULL) {
            memcpy(ret, addr, length);
            return ret;
        }
    }
    return NULL;
}

wchar_t *wcsdup(const wchar_t *s)
{
    if(s != NULL) {
        return memdup(s, (lstrlenW(s) + 1) * sizeof(wchar_t));
    }
    return NULL;
}

void clsid_to_string(REFCLSID rclsid, char *buf)
{
    const uint8_t *ptr = (const uint8_t *) rclsid;

    our_snprintf(buf, 64, "{%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x}",
        ptr[3], ptr[2], ptr[1], ptr[0], ptr[5], ptr[4], ptr[7], ptr[6],
        ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
}

void wsabuf_get_buffer(uint32_t buffer_count, const WSABUF *buffers,
    uint8_t **ptr, uintptr_t *length)
{
    *length = 0;
    for (uint32_t idx = 0; idx < buffer_count; idx++) {
        *length += buffers[idx].len;
    }

    *ptr = (uint8_t *) mem_alloc(*length);
    if(*ptr != NULL) {
        for (uint32_t idx = 0, offset = 0; idx < buffer_count; idx++) {
            if(buffers[idx].buf != NULL && buffers[idx].len != 0) {
                memcpy(&(*ptr)[offset], buffers[idx].buf, buffers[idx].len);
                offset += buffers[idx].len;
            }
        }
    }
}

uint64_t hash_buffer(const void *buf, uint32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    const uint8_t *p = (const uint8_t *) buf;
    uint64_t ret = *p << 7;
    for (uint32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ *p++;
    }
    return ret ^ length;
}

uint64_t hash_string(const char *buf, int32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    if(length < 0) {
        length = strlen(buf);
    }

    uint64_t ret = *buf << 7;
    for (int32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ (uint8_t) *buf++;
    }
    return ret ^ length;
}

uint64_t hash_stringW(const wchar_t *buf, int32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    if(length < 0) {
        length = lstrlenW(buf);
    }

    uint64_t ret = *buf << 7;
    for (int32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ (uint16_t) *buf++;
    }
    return ret ^ length;
}

uint64_t hash_uint64(uint64_t value)
{
    return hash_buffer(&value, sizeof(value));
}

// http://stackoverflow.com/questions/9655202/how-to-convert-integer-to-string-in-c
int ultostr(intptr_t value, char *str, int base)
{
    const char charset[] = "0123456789abcdef"; int length = 0;

    // Negative values.
    if(value < 0 && base == 10) {
        *str++ = '-', length++;
        value = -value;
    }

    // Calculate the amount of numbers required.
    uintptr_t shifter = value, uvalue = value;
    do {
        str++, length++, shifter /= base;
    } while (shifter);

    // Populate the string.
    *str = 0;
    do {
        *--str = charset[uvalue % base];
        uvalue /= base;
    } while (uvalue);
    return length;
}

static uintptr_t _min(uintptr_t a, uintptr_t b)
{
    return a < b ? a : b;
}

int our_vsnprintf(char *buf, int length, const char *fmt, va_list args)
{
    const char *base = buf;
    for (; *fmt != 0 && length > 1; fmt++) {
        if(*fmt != '%') {
            *buf++ = *fmt, length--;
            continue;
        }

        const char *s; char tmp[32]; uintptr_t p; intptr_t v, l;

        switch (*++fmt) {
        case 's':
            s = va_arg(args, const char *);
            strncpy(buf, s, length-1);
            l = _min(length-1, strlen(s));
            buf += l, length -= l;
            break;

        case 'p':
            p = va_arg(args, uintptr_t);
            if(length > 10) {
                *buf++ = '0', *buf++ = 'x';
                l = ultostr(p, buf, 16);
                length -= 2 + l, buf += l;
            }
            break;

        case 'x':
            p = va_arg(args, uint32_t);
            if(length > 8) {
                l = ultostr(p, buf, 16);
                // Prepend a single '0' if uneven.
                if((l & 1) != 0) {
                    *buf++ = '0', length--;
                    l = ultostr(p, buf, 16);
                }
                length -= l, buf += l;
            }
            break;

        case 'd':
            v = va_arg(args, int32_t);
            l = ultostr(v >= 0 ? v : -v, tmp, 10);
            if(length > l + (v < 0)) {
                if(v < 0) {
                    v = -v, *buf++ = '-', length--;
                }
                l = ultostr(v, buf, 10);
                length -= l, buf += l;
            }
            break;

        default:
            dpipe("CRITICAL:Unhandled vsnprintf modifier: %s", 4, fmt);
        }
    }
    *buf = 0;
    return buf - base;
}

int our_snprintf(char *buf, int length, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    int ret = our_vsnprintf(buf, length, fmt, args);

    va_end(args);
    return ret;
}

int our_memcmp(const void *a, const void *b, uint32_t length)
{
    const uint8_t *_a = (const uint8_t *) a, *_b = (const uint8_t *) b;
    for (; length != 0; _a++, _b++, length--) {
        if(*_a != *_b) {
            return *_a - *_b;
        }
    }
    return 0;
}

uint32_t our_strlen(const char *s)
{
    uint32_t ret = 0;
    while (*s != 0) {
        ret++, s++;
    }
    return ret;
}

void hexencode(char *dst, const uint8_t *src, uint32_t length)
{
    static const char charset[] = "0123456789abcdef";
    for (; length != 0; src++, length--) {
        *dst++ = charset[*src >> 4];
        *dst++ = charset[*src & 15];
    }
    *dst = 0;
}

void sha1(const void *buffer, uintptr_t buflen, char *hexdigest)
{
    SHA1Context ctx;
    SHA1Reset(&ctx);
    SHA1Input(&ctx, buffer, buflen);
    SHA1Result(&ctx);

    const uint32_t *digest = (const uint32_t *) ctx.Message_Digest;
    for (uint32_t idx = 0; idx < 5; idx++) {
        // TODO Our custom snprintf doesn't have proper %08x support yet.
        hexdigest += our_snprintf(hexdigest, 32, "%x%x%x%x",
            (digest[idx] >> 24) & 0xff,
            (digest[idx] >> 16) & 0xff,
            (digest[idx] >>  8) & 0xff,
            (digest[idx] >>  0) & 0xff);
    }
}
