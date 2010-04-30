#include "buffer.h"
#include <string.h>
#include <stdlib.h>

struct _Buffer {
    void *data;
    size_t length;
};

Buffer*buffer_empty(size_t length) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (buf == NULL)
        return NULL;
    buf->data = calloc(length, 1);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }
    buf->length = length;
    return buf;
}
Buffer* buffer_new(const void *data, size_t length) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (buf == NULL)
        return NULL;
    buf->length = length;
    if (length > 0) {
        buf->data = malloc(length);
        if (buf->data == NULL) {
            free(buf);
            return NULL;
        }
        memcpy(buf->data, data, length);
    } else {
        buf->data = NULL;
    }
    return buf;
}

Buffer* buffer_copy(const Buffer *buf) {
    if (buf != NULL)
        return buffer_new(buf->data, buf->length);
    else
        return NULL;
}

void buffer_free(Buffer *buf) {
    if (buf == NULL)
        return;
    if (buf->length > 0)
        free(buf->data);
    free(buf);
}

void *buffer_data(const Buffer *buf) {
    if (buf == NULL)
        return NULL;
    return buf->data;
}

size_t buffer_length(const Buffer *buf) {
    if (buf == NULL)
        return 0;
    return buf->length;
}
