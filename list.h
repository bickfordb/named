#include <stdbool.h>

#ifndef __LIST_H__
#define __LIST_H__

struct _List;
typedef struct _List List;
typedef void (*ListIterateFunc)(List *sublist, void *context, void *item, bool *stop);
typedef void (*ListFreeItemFunc)(void *item);
typedef char *(*ListReprFunc)(void *item);
List *list_new();
void list_prepend(List *list, void *item);
void list_append(List *list, void *item);
void list_free(List *list, ListFreeItemFunc func);
void list_iterate(List *list, ListIterateFunc iterate_func, void *context);
int list_length(List *list); 
char *list_repr(List *list, ListReprFunc repr_func);

#endif // __LIST_H__
