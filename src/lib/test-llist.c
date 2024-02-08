/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "llist.h"


struct dllist {
	struct dllist *prev, *next;
};

static void test_dllist(void)
{
	struct dllist *head = NULL, *l4, *l3, *l2, *l1;
	struct dllist empty = { NULL, NULL };

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
	/* removal of an entry not in the list shouldn't cause the list to break */
	DLLIST_REMOVE(&head, &empty);
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
	struct dllist empty = { NULL, NULL };

	l4 = t_new(struct dllist, 1);
	l3 = t_new(struct dllist, 1);
	l2 = t_new(struct dllist, 1);
	l1 = t_new(struct dllist, 1);

	test_begin("dllist2");
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
	/* removal of an entry not in the list shouldn't cause the list to break */
	DLLIST2_REMOVE(&head, &tail, &empty);
	test_assert(head == l1);
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

static void test_dllist2_join(void)
{
	struct dllist *head, *tail, *elem[4];
	struct dllist *head2, *tail2, *elem2[N_ELEMENTS(elem)];

	test_begin("dllist2 join");
	for (unsigned int i = 0; i < N_ELEMENTS(elem); i++) {
		elem[i] = t_new(struct dllist, 1);
		elem2[i] = t_new(struct dllist, 1);
	}
	for (unsigned int i = 0; i < N_ELEMENTS(elem); i++) {
		for (unsigned int j = 0; j < N_ELEMENTS(elem2); j++) {
			head = tail = head2 = tail2 = NULL;
			for (unsigned int n = 0; n < i; n++)
				DLLIST2_APPEND(&head, &tail, elem[n]);
			for (unsigned int n = 0; n < j; n++)
				DLLIST2_APPEND(&head2, &tail2, elem2[n]);
			DLLIST2_JOIN(&head, &tail, &head2, &tail2);

			/* verify */
			struct dllist *tmp = head, *last = NULL;
			for (unsigned int n = 0; n < i; n++) {
				test_assert(tmp == elem[n]);
				last = tmp;
				tmp = tmp->next;
			}
			for (unsigned int n = 0; n < j; n++) {
				test_assert(tmp == elem2[n]);
				last = tmp;
				tmp = tmp->next;
			}
			test_assert(tmp == NULL);
			test_assert(tail == last);
		}
	}
	test_end();
}

void test_llist(void)
{
	test_dllist();
	test_dllist2();
	test_dllist2_join();
}
