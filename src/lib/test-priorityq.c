/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "priorityq.h"

#include <stdlib.h>

struct pq_test_item {
	struct priorityq_item item;
	int num;
};

static int cmp_int(const void *p1, const void *p2)
{
	const struct pq_test_item *i1 = p1, *i2 = p2;

	return i1->num - i2->num;
}

void test_priorityq(void)
{
#define PQ_MAX_ITEMS 100
	static const int input[] = {
		1, 2, 3, 4, 5, 6, 7, 8, -1,
		8, 7, 6, 5, 4, 3, 2, 1, -1,
		8, 7, 5, 6, 1, 3, 4, 2, -1,
		-1
	};
	static const int output[] = {
		1, 2, 3, 4, 5, 6, 7, 8
	};
	struct pq_test_item *item, items[PQ_MAX_ITEMS];
	struct priorityq_item *const *all_items;
	unsigned int i, j;
	struct priorityq *pq;
	pool_t pool;
	int prev;

	pool = pool_alloconly_create("priorityq items", 1024);

	/* simple tests with popping only */
	test_begin("priorityq");
	for (i = 0; input[i] != -1; i++) {
		p_clear(pool);
		pq = priorityq_init(cmp_int, 1);
		for (j = 0; input[i] != -1; i++, j++) {
			test_assert(priorityq_count(pq) == j);
			item = p_new(pool, struct pq_test_item, 1);
			item->num = input[i];
			priorityq_add(pq, &item->item);
		}
		all_items = priorityq_items(pq);
		test_assert(priorityq_count(pq) == N_ELEMENTS(output));
		item = (struct pq_test_item *)all_items[0];
		test_assert(item->num == output[0]);
		for (j = 1; j < N_ELEMENTS(output); j++) {
			item = (struct pq_test_item *)all_items[j];
			test_assert(item->num > output[0]);
			test_assert(item->num <= output[N_ELEMENTS(output)-1]);
		}
		for (j = 0; j < N_ELEMENTS(output); j++) {
			test_assert(priorityq_count(pq) == N_ELEMENTS(output) - j);

			item = (struct pq_test_item *)priorityq_peek(pq);
			test_assert(output[j] == item->num);
			item = (struct pq_test_item *)priorityq_pop(pq);
			test_assert(output[j] == item->num);
		}
		test_assert(priorityq_count(pq) == 0);
		test_assert(priorityq_peek(pq) == NULL);
		test_assert(priorityq_pop(pq) == NULL);
		priorityq_deinit(&pq);
	}
	test_end();

	/* randomized tests, remove elements */
	test_begin("priorityq randomized");
	for (i = 0; i < 100; i++) {
		pq = priorityq_init(cmp_int, 1);
		for (j = 0; j < PQ_MAX_ITEMS; j++) {
			items[j].num = rand();
			priorityq_add(pq, &items[j].item);
		}
		for (j = 0; j < PQ_MAX_ITEMS; j++) {
			if (rand() % 3 == 0) {
				priorityq_remove(pq, &items[j].item);
				items[j].num = -1;
			}
		}
		prev = 0;
		while (priorityq_count(pq) > 0) {
			item = (struct pq_test_item *)priorityq_pop(pq);
			test_assert(item->num >= 0 && prev <= item->num);
			prev = item->num;
			item->num = -1;
		}
		for (j = 0; j < PQ_MAX_ITEMS; j++) {
			test_assert(items[j].num == -1);
		}
		priorityq_deinit(&pq);
	}
	test_end();
	pool_unref(&pool);
}
