#ifndef __LIST_H__
#define __LIST_H__
#include <stdbool.h>
#include "rope.h"

struct _List;
typedef struct _List List;
typedef void (*ListIterateFunc)(List *list, void *context, void *item, bool *stop);
typedef void (*ListFreeItemFunc)(void *item);
typedef void *(*ListCopyFunc)(void *item);
typedef void (*ListReprFunc)(void *item, Rope *rope);
List *list_new();
void list_prepend(List *list, void *item);
void list_append(List *list, void *item);
void list_free(List *list, ListFreeItemFunc func);
void list_iterate(List *list, ListIterateFunc iterate_func, void *context);
int list_length(List *list); 
void list_repr(List *list, Rope *rope, ListReprFunc repr_func);
List *list_copy(List *list, ListCopyFunc copy_func);

#endif // __LIST_H__
