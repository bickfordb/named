#include <string.h>
#include <stdlib.h>
#include "util.h"

char *string_copy(const char *orig) { 
    if (orig == NULL)
        return NULL;
    size_t n = strlen(orig) + 1;
    char *copy = malloc(n);
    if (copy != NULL)
        memcpy(copy, orig, n);
    return copy;
}
