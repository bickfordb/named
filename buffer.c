#include "buffer.h"
#include <string.h>
#include <stdlib.h>

struct _Buffer { 
    void *data;
    size_t length;  
};

Buffer* buffer_new(void *data, size_t length) {
    Buffer *buf = malloc(sizeof(Buffer));
    buf->length = length;
    if (length > 0) {
        buf->data = malloc(length);
        memcpy(buf->data, data, length);
    } else {
        buf->data = NULL;
    }
    return buf;
}

Buffer* buffer_copy(Buffer *buf) {
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
void *buffer_data(Buffer *buf) { 
    if (buf == NULL)
        return NULL;
    return buf->data;
}
size_t buffer_length(Buffer *buf) {
    if (buf == NULL)
        return 0;
    return buf->length;
}
