#ifndef LLIST_H
#define LLIST_H

/* Doubly linked list */
#define DLLIST_PREPEND(list, item) STMT_START { \
	(item)->prev = NULL; \
	(item)->next = *(list); \
	if (*(list) != NULL) (*(list))->prev = (item); \
	*(list) = (item); \
	} STMT_END

#define DLLIST_REMOVE(list, item) STMT_START { \
	if ((item)->prev == NULL) \
		*(list) = (item)->next; \
	else \
		(item)->prev->next = (item)->next; \
	if ((item)->next != NULL) { \
		(item)->next->prev = (item)->prev; \
		(item)->next = NULL; \
	} \
	(item)->prev = NULL; \
	} STMT_END

#endif
