/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "llist.h"

#include <stdlib.h>

struct dllist {
	struct dllist *prev, *next;
};

static void test_dllist(void)
{
	struct dllist *head = NULL, *l4, *l3, *l2, *l1;

	l4 = t_new(struct dllist, 1);
	l3 = t_new(struct dllist, 1);
	l2 = t_new(struct dllist, 1);
	l1 = t_new(struct dllist, 1);

	test_begin("dllist");
	DLLIST_PREPEND(&head, l4);
	test_assert(head == l4);
	test_assert(l4->prev == NULL && l4->next == NULL);
	DLLIST_PREPEND(&head, l3);
	test_assert(head == l3);
	test_assert(l3->prev == NULL && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	DLLIST_PREPEND(&head, l2);
	DLLIST_PREPEND(&head, l1);
	/* remove from middle */
	DLLIST_REMOVE(&head, l2);
	test_assert(l2->prev == NULL && l2->next == NULL);
	test_assert(head == l1);
	test_assert(l1->prev == NULL && l1->next == l3);
	test_assert(l3->prev == l1 && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	/* remove from head */
	DLLIST_REMOVE(&head, l1);
	test_assert(l1->prev == NULL && l1->next == NULL);
	test_assert(head == l3);
	test_assert(l3->prev == NULL && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	/* remove from tail */
	DLLIST_PREPEND(&head, l1);
	DLLIST_REMOVE(&head, l4);
	test_assert(l4->prev == NULL && l4->next == NULL);
	test_assert(head == l1);
	test_assert(l1->prev == NULL && l1->next == l3);
	test_assert(l3->prev == l1 && l3->next == NULL);
	/* remove last two */
	DLLIST_REMOVE(&head, l1);
	DLLIST_REMOVE(&head, l3);
	test_assert(l3->prev == NULL && l3->next == NULL);
	test_assert(head == NULL);
	test_end();
}

static void test_dllist2(void)
{
	struct dllist *head = NULL, *tail = NULL, *l4, *l3, *l2, *l1;

	l4 = t_new(struct dllist, 1);
	l3 = t_new(struct dllist, 1);
	l2 = t_new(struct dllist, 1);
	l1 = t_new(struct dllist, 1);

	test_begin("dllist");
	/* prepend to empty */
	DLLIST2_PREPEND(&head, &tail, l3);
	test_assert(head == l3 && tail == l3);
	test_assert(l3->next == NULL && l3->prev == NULL);
	/* remove last */
	DLLIST2_REMOVE(&head, &tail, l3);
	test_assert(head == NULL && tail == NULL);
	test_assert(l3->next == NULL && l3->prev == NULL);
	/* append to empty */
	DLLIST2_APPEND(&head, &tail, l3);
	test_assert(head == l3 && tail == l3);
	test_assert(l3->next == NULL && l3->prev == NULL);
	/* prepend */
	DLLIST2_PREPEND(&head, &tail, l2);
	test_assert(head == l2 && tail == l3);
	test_assert(l2->prev == NULL && l2->next == l3);
	test_assert(l3->prev == l2 && l3->next == NULL);
	/* append */
	DLLIST2_APPEND(&head, &tail, l4);
	test_assert(head == l2 && tail == l4);
	test_assert(l2->prev == NULL && l2->next == l3);
	test_assert(l3->prev == l2 && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	DLLIST2_PREPEND(&head, &tail, l1);

	/* remove from middle */
	DLLIST2_REMOVE(&head, &tail, l2);
	test_assert(l2->prev == NULL && l2->next == NULL);
	test_assert(head == l1 && tail == l4);
	test_assert(l1->prev == NULL && l1->next == l3);
	test_assert(l3->prev == l1 && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	/* remove from head */
	DLLIST2_REMOVE(&head, &tail, l1);
	test_assert(l1->prev == NULL && l1->next == NULL);
	test_assert(head == l3 && tail == l4);
	test_assert(l3->prev == NULL && l3->next == l4);
	test_assert(l4->prev == l3 && l4->next == NULL);
	/* remove from tail */
	DLLIST2_PREPEND(&head, &tail, l1);
	DLLIST2_REMOVE(&head, &tail, l4);
	test_assert(l4->prev == NULL && l4->next == NULL);
	test_assert(head == l1 && tail == l3);
	test_assert(l1->prev == NULL && l1->next == l3);
	test_assert(l3->prev == l1 && l3->next == NULL);
	/* remove last two */
	DLLIST2_REMOVE(&head, &tail, l1);
	DLLIST2_REMOVE(&head, &tail, l3);
	test_assert(l3->prev == NULL && l3->next == NULL);
	test_assert(head == NULL && tail == NULL);
	test_end();
}

void test_llist(void)
{
	test_dllist();
	test_dllist2();
}
