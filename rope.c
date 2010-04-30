#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "rope.h"
#include "list.h"

struct _Rope {
    List *buffers;
    size_t length; 
};

Rope *rope_new() { 
    Rope *r = calloc(1, sizeof(Rope));
    r->buffers = list_new();
    return r;
}
void rope_append_cstr(Rope *r, const char *s) {
    size_t len = strlen(s) + 1;
    Buffer *b = buffer_new((void *)s, len);    
    list_append(r->buffers, b);
    r->length += len;
}

void rope_append_bytes(Rope *r, const uint8_t *bytes, size_t len) {
    list_append(r->buffers, buffer_new(bytes, len));    
    r->length += len;
}

void rope_append_buffer(Rope *r, const Buffer *buffer) { 
    list_append(r->buffers, buffer_copy(buffer));
    r->length += buffer_length(buffer);
}

size_t rope_length(const Rope *r) { 
    return r->length;
}

Buffer *rope_flatten(const Rope *r) {
    Buffer *buf = buffer_empty(r->length);
    size_t counter = 0;
    void visitor(List *l, void *ctx, void *item, bool *keep_going) {
        Buffer *buf_item = (Buffer *)item;
        memcpy(buffer_data(buf) + counter, buffer_data(buf_item), buffer_length(buf_item));
        counter += buffer_length(buf_item);
    }
    list_iterate(r->buffers, visitor, NULL);
    return buf;
}

void rope_free(Rope *r) { 
    list_free(r->buffers, (ListFreeItemFunc)buffer_free);
    free(r);
}

