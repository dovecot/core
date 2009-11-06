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

/* Doubly linked list with head and tail */
#define DLLIST2_PREPEND(head, tail, item) STMT_START { \
	(item)->prev = NULL; \
	(item)->next = *(head); \
	if (*(head) != NULL) (*(head))->prev = (item); else (*tail) = (item); \
	*(head) = (item); \
	} STMT_END

#define DLLIST2_APPEND(head, tail, item) STMT_START { \
	(item)->prev = *(tail); \
	(item)->next = NULL; \
	if (*(tail) != NULL) (*(tail))->next = (item); else (*head) = (item); \
	*(tail) = (item); \
	} STMT_END

#define DLLIST2_REMOVE(head, tail, item) STMT_START { \
	if ((item)->prev == NULL) \
		*(head) = (item)->next; \
	else \
		(item)->prev->next = (item)->next; \
	if ((item)->next == NULL) \
		*(tail) = (item)->prev; \
	else { \
		(item)->next->prev = (item)->prev; \
		(item)->next = NULL; \
	} \
	(item)->prev = NULL; \
	} STMT_END

#endif
