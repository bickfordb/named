#include <stdlib.h>
#include "list.h"

struct _List { 
    void *next;
    void *item;
};

List *list(void *item) {
    return list_cons(NULL, item);
}

List *list_cons(List *tail, void *item) {
    List *head = malloc(sizeof(List));
    head->item = item;
    head->next = tail;
    return head;
}

void list_free(List *list, ListFreeItemFunc free_func) {
    if (list->next != NULL) 
        list_free(list, free_func);     
    if (list->item != NULL)
        free_func(list->item);
    free(list);
}

void list_iterate(List *list, ListIterateFunc iterate_func, void *context) {
    bool keep_going = true;
    while (keep_going && list != NULL) {
        iterate_func(list, context, list->item, &keep_going);
        list = list->next; 
    }
}

int list_length(List *list) {
    int i = 0;
    while (list != NULL) { 
        i++;
        list = list->next;
    }
    return i;
}

