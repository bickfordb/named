#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "rope.h"
#include "list.h"
#include "log.h"

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

Buffer *rope_slice(Rope *r, ssize_t start, ssize_t end) {
    size_t offset = 0;
    if (start < 0)
        start = r->length + start;
    if (end < 0)
        end = r->length + end;
    
    if (start > end) {
        ssize_t temp = start;
        start = end;
        end = temp;
    }
    if (start >= r->length) {
        start = r->length - 1;
    } else if (start < 0)
        start = 0;


    if (end >= r->length) {
        end = r->length - 1;
    } else if (end < 0)
        end = 0;

    size_t result_len = end - start;
    Buffer *result = buffer_empty(result_len);
    uint8_t *result_data = buffer_data(result);
    size_t result_offset = 0;
    void visitor(List *l, void *ctx, void *item, bool *keep_going) {
        Buffer *segment_buf = (Buffer *)item;
        ssize_t a = offset;
        ssize_t b = offset + buffer_length(segment_buf);
        size_t segment_offset = offset;
        size_t segment_len = 0;

        // There are six cases for segment overlap:
        // 1. ----S---A----E---B
        // 2. ----S---A----B---E
        // 3. ----S---E----A---B (no overlap)
        // 4. ----A---S----E---B
        // 5. ----A---S----B---E
        // 6. ----A---B----S---E (no overlap)
        if ((a >= start) && (end >= a) && (b >= end)) {
            segment_offset = a;
            segment_len = end - segment_offset;
        } else if ((start <= a) && (a <= b) && (b <= end)) {
            segment_offset = a;
            segment_len = b - segment_offset;
        } else if ((start <= end) && (end <= a) && (a <= b)) {
            // no overlap
            *keep_going = false;
        } else if ((a <= start) && (start <= end) && (end <= b)) {
            segment_offset = start;
            segment_len = end - segment_offset;
        } else if ((a <= start) && (start <= b) && (b <= end)) {
            segment_offset = start;
            segment_len = b - segment_offset;
        } else if ((a <= b) && (b <= start) && (start <= end)) {
            ; // no overlap
        }
        
        if (segment_len > 0) {
            memcpy(result_data + result_offset, buffer_data(segment_buf) + segment_offset, segment_len);
            result_offset += segment_len;
        }
        offset += buffer_length(segment_buf);
    }
    list_iterate(r->buffers, visitor, NULL);
    return result;
}


