#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "list.h"

struct _ListItem;
struct _List { 
    struct _ListItem *head;
    struct _ListItem *tail;
    int size;
};

struct _ListItem {
    struct _ListItem *next;
    void *value;
};

typedef struct _ListItem ListItem;

List *list_new() {
    return calloc(1, sizeof(List));
}

void list_append(List *list, void *item) { 
    ListItem *list_item = calloc(1, sizeof(ListItem));
    list_item->value = item;
    if (list->head == NULL) {
        list->head = list_item;
        list->tail = list_item;
    } else {
        list->tail->next = list_item;
        list->tail = list_item;
    }     
    list->size++;
}

void list_prepend(List *list, void *item) { 
    ListItem *list_item = calloc(1, sizeof(ListItem));
    list_item->value = item;
    if (list->head == NULL) {
        list->head = list_item;
        list->tail = list_item;
    } else {
        list_item->next = list->head;
        list->head = list_item;
    }     
    list->size++;
}

void list_free(List *list, ListFreeItemFunc free_func) {
    ListItem *i = list->head; 
    while (i != NULL) {
        free_func(i->value);
        ListItem *last = i;
        i = i->next;
        free(last);
    }
    free(list);
}

void list_iterate(List *list, ListIterateFunc iterate_func, void *context) {
    bool keep_going = true;
    ListItem *i = list->head;
    while (keep_going && i != NULL) {
        iterate_func(list, context, i->value, &keep_going);
        i = i->next; 
    }
}

int list_length(List *list) {
    return list->size;
}

char *list_repr(List *list, ListReprFunc repr_func) {
    ListItem *i = list->head;
    int idx = 0;
    char *repr = NULL;
    while (i != NULL) {
        char *val_repr = repr_func(i->value);
        if (repr == NULL)
            asprintf(&repr, "[%s", val_repr);
        else {
            char *old_repr = repr;
            asprintf(&repr, "%s, %s", repr, val_repr);
            free(old_repr); 
        }
        free(val_repr);
        i = i->next;
    }
    char *old_repr = repr;
    asprintf(&repr, "%s]", repr);
    free(old_repr);
    return repr;
}

List *list_copy(List *other, ListCopyFunc copy_func) {
    List *list = list_new();
    void visitor(List *some_list, void *ctx, void *item, bool *keep_going) {
        list_append(list, copy_func(item));
    }
    list_iterate(other, visitor, NULL);
    return list;
}

