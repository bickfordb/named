/* buffer: useful for passing around byte buckets
 *
 * This is just a heap allocated tuple of (void *, size_t)
 */ 

#ifndef __BUFFER_H__
#define __BUFFER_H__
#include <stdlib.h>
typedef struct _Buffer Buffer;
Buffer* buffer_new(const void *data, size_t length);
Buffer* buffer_empty(size_t length);
Buffer* buffer_copy(const Buffer *);
void buffer_free(Buffer *);
void *buffer_data(const Buffer *);
size_t buffer_length(const Buffer *);
void buffer_set_data(Buffer *, const void *data, size_t length);
#endif // __BUFFER_H__

