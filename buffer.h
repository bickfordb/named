#ifndef __BUFFER_H__
#define __BUFFER_H__
#include <stdlib.h>
typedef struct _Buffer Buffer;
Buffer* buffer_new(void *data, size_t length);
Buffer* buffer_copy(Buffer *);
void buffer_free(Buffer *);
void *buffer_data(Buffer *);
size_t buffer_length(Buffer *);
void buffer_set_data(Buffer *, void *data, size_t length);
#endif // __BUFFER_H__

