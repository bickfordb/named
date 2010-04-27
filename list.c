#include <stdlib.h>
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
    for (;;) {
        if (i == NULL)
            break;
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

