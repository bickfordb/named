/* string buffer with o(1) append and o(n) other ops 
 * (not technically rope but in the same spirit)
 * */

#ifndef __ROPE_H__
#define __ROPE_H__
#include <stdint.h>
#include "buffer.h"

typedef struct _Rope Rope;

Rope *rope_new();
void rope_append_cstr(Rope *r, const char *s);
void rope_append_bytes(Rope *r, const uint8_t *bytes, size_t len);
void rope_append_buffer(Rope *r, const Buffer *buffer);
Buffer *rope_slice(Rope *r, ssize_t start, ssize_t end);
size_t rope_length(const Rope *r);
Buffer *rope_flatten(const Rope *r);
void rope_free(Rope *r);

#endif // __ROPE_H__

