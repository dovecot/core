/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"
#include "str.h"
#include "base64.h"
#include "bsearch-insert-pos.h"
#include "aqueue.h"
#include "priorityq.h"
#include "seq-range-array.h"
#include "str-sanitize.h"
#include "utc-mktime.h"

#include <stdlib.h>
#include <time.h>

static void test_base64_encode(void)
{
	static const char *input[] = {
		"hello world",
		"foo barits",
		"just niin"
	};
	static const char *output[] = {
		"aGVsbG8gd29ybGQ=",
		"Zm9vIGJhcml0cw==",
		"anVzdCBuaWlu"
	};
	string_t *str;
	unsigned int i;
	bool success;

	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base64_encode(input[i], strlen(input[i]), str);
		success = strcmp(output[i], str_c(str)) == 0;
		test_out(t_strdup_printf("base64_encode(%d)", i), success);
	}
}

struct test_base64_decode_output {
	const char *text;
	int ret;
	unsigned int src_pos;
};

static void test_base64_decode(void)
{
	static const char *input[] = {
		"\taGVsbG8gd29ybGQ=",
		"\nZm9v\n \tIGJh  \t\ncml0cw==",
		"  anVzdCBuaWlu  \n",
		"aGVsb",
		"aGVsb!!!!!",
		"aGVs!!!!!"
	};
	static const struct test_base64_decode_output output[] = {
		{ "hello world", 0, -1 },
		{ "foo barits", 0, -1 },
		{ "just niin", 1, -1 },
		{ "hel", 1, 4 },
		{ "hel", -1, 4 },
		{ "hel", -1, 4 }
	};
	string_t *str;
	unsigned int i;
	size_t src_pos;
	int ret;
	bool success;

	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);

		src_pos = 0;
		ret = base64_decode(input[i], strlen(input[i]), &src_pos, str);

		success = output[i].ret == ret &&
			strcmp(output[i].text, str_c(str)) == 0 &&
			(src_pos == output[i].src_pos ||
			 (output[i].src_pos == (unsigned int)-1 &&
			  src_pos == strlen(input[i])));
		test_out(t_strdup_printf("base64_decode(%d)", i), success);
	}
}

static int cmp_uint(const void *p1, const void *p2)
{
	const unsigned int *i1 = p1, *i2 = p2;

	return *i1 - *i2;
}

static void test_bsearch_insert_pos(void)
{
	static const unsigned int input[] = {
		1, 5, 9, 15, 16, -1,
		1, 5, 9, 15, 16, 17, -1,
		-1
	};
	static const unsigned int max_key = 18;
	const unsigned int *cur;
	unsigned int key, len, i, idx;
	bool success;

	cur = input;
	for (i = 0; cur[0] != -1U; i++) {
		for (len = 0; cur[len] != -1U; len++) ;
		for (key = 0; key < max_key; key++) {
			if (bsearch_insert_pos(&key, cur, len, sizeof(*cur),
					       cmp_uint, &idx))
				success = cur[idx] == key;
			else if (idx == 0)
				success = cur[0] > key;
			else if (idx == len)
				success = cur[len-1] < key;
			else {
				success = cur[idx-1] < key &&
					cur[idx+1] > key;
			}
			if (!success)
				break;
		}
		cur += len + 1;

		test_out(t_strdup_printf("bsearch_insert_pos(%d,%d)", i, key),
			 success);
	}
}

static bool aqueue_is_ok(struct aqueue *aqueue, unsigned int deleted_n)
{
	const unsigned int *p;
	unsigned int n, i, count;

	count = aqueue_count(aqueue);
	for (i = 0, n = 1; i < count; i++, n++) {
		p = array_idx_i(aqueue->arr, aqueue_idx(aqueue, i));
		if (i == deleted_n)
			n++;
		if (*p != n)
			return FALSE;
	}
	return TRUE;
}

static const unsigned int aqueue_input[] = { 1, 2, 3, 4, 5, 6 };
static const char *test_aqueue2(unsigned int initial_size)
{
	ARRAY_DEFINE(aqueue_array, unsigned int);
	unsigned int i, j, k;
	struct aqueue *aqueue;

	for (i = 0; i < N_ELEMENTS(aqueue_input); i++) {
		for (k = 0; k < N_ELEMENTS(aqueue_input); k++) {
			t_array_init(&aqueue_array, initial_size);
			aqueue = aqueue_init(&aqueue_array.arr);
			aqueue->head = aqueue->tail = initial_size - 1;
			for (j = 0; j < k; j++) {
				aqueue_append(aqueue, &aqueue_input[j]);
				if (aqueue_count(aqueue) != j + 1) {
					return t_strdup_printf("Wrong count after append %u vs %u)",
							       aqueue_count(aqueue), j + 1);
				}
				if (!aqueue_is_ok(aqueue, -1U))
					return "Invalid data after append";
			}

			if (k != 0 && i < k) {
				aqueue_delete(aqueue, i);
				if (aqueue_count(aqueue) != k - 1)
					return "Wrong count after delete";
				if (!aqueue_is_ok(aqueue, i))
					return "Invalid data after delete";
			}
		}
	}
	aqueue_clear(aqueue);
	if (aqueue_count(aqueue) != 0)
		return "aqueue_clear() broken";
	return NULL;
}

static void test_aqueue(void)
{
	unsigned int i;
	const char *reason = NULL;

	for (i = 1; i <= N_ELEMENTS(aqueue_input) + 1 && reason == NULL; i++) {
		T_FRAME(
			reason = test_aqueue2(i);
		);
	}
	test_out_reason("aqueue", reason == NULL, reason);
}

static bool mem_has_bytes(const void *mem, size_t size, uint8_t b)
{
	const uint8_t *bytes = mem;
	unsigned int i;

	for (i = 0; i < size; i++) {
		if (bytes[i] != b)
			return FALSE;
	}
	return TRUE;
}

static void test_mempool_alloconly(void)
{
#define PMALLOC_MAX_COUNT 128
	pool_t pool;
	unsigned int i, j, k;
	void *mem[PMALLOC_MAX_COUNT + 1];
	bool success = TRUE;

	for (i = 0; i < 64; i++) {
		for (j = 1; j <= 128; j++) {
			pool = pool_alloconly_create(MEMPOOL_GROWING"test", i);
			mem[0] = p_malloc(pool, j);
			memset(mem[0], j, j);

			for (k = 1; k <= PMALLOC_MAX_COUNT; k++) {
				mem[k] = p_malloc(pool, k);
				memset(mem[k], k, k);
			}

			if (!mem_has_bytes(mem[0], j, j))
				success = FALSE;
			for (k = 1; k <= PMALLOC_MAX_COUNT; k++) {
				if (!mem_has_bytes(mem[k], k, k))
					success = FALSE;
			}
			pool_unref(&pool);
		}
	}
	test_out("mempool_alloconly", success);
}

struct pq_test_item {
	struct priorityq_item item;
	int num;
};

static int cmp_int(const void *p1, const void *p2)
{
	const struct pq_test_item *i1 = p1, *i2 = p2;

	return i1->num - i2->num;
}

static void test_priorityq(void)
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
	unsigned int i, j;
	struct priorityq *pq;
	pool_t pool;
	int prev;
	bool success = TRUE;

	pool = pool_alloconly_create("priorityq items", 1024);

	/* simple tests with popping only */
	for (i = 0; input[i] != -1; i++) {
		p_clear(pool);
		pq = priorityq_init(cmp_int, 1);
		for (j = 0; input[i] != -1; i++, j++) {
			if (priorityq_count(pq) != j)
				success = FALSE;
			item = p_new(pool, struct pq_test_item, 1);
			item->num = input[i];
			priorityq_add(pq, &item->item);
		}
		for (j = 0; j < N_ELEMENTS(output); j++) {
			if (priorityq_count(pq) != N_ELEMENTS(output) - j)
				success = FALSE;

			item = (struct pq_test_item *)priorityq_peek(pq);
			if (output[j] != item->num)
				success = FALSE;
			item = (struct pq_test_item *)priorityq_pop(pq);
			if (output[j] != item->num)
				success = FALSE;
		}
		if (priorityq_count(pq) != 0)
			success = FALSE;
		if (priorityq_peek(pq) != NULL || priorityq_pop(pq) != NULL)
			success = FALSE;
		priorityq_deinit(&pq);
	}
	test_out("priorityq(1)", success);

	/* randomized tests, remove elements */
	success = TRUE;
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
			if (item->num < 0 || prev > item->num)
				success = FALSE;
			prev = item->num;
			item->num = -1;
		}
		for (j = 0; j < PQ_MAX_ITEMS; j++) {
			if (items[j].num != -1)
				success = FALSE;
		}
		priorityq_deinit(&pq);
	}
	test_out("priorityq(2)", success);
	pool_unref(&pool);
}

static void test_seq_range_array(void)
{
	static const unsigned int input_min = 1, input_max = 5;
	static const unsigned int input[] = {
		1, 2, 3, 4, 5, -1U,
		2, 3, 4, -1U,
		1, 2, 4, 5, -1U,
		1, 3, 5, -1U,
		1, -1U,
		5, -1U,
		-1U
	};
	ARRAY_TYPE(seq_range) range = ARRAY_INIT;
	unsigned int i, j, seq, start, num;
	bool old_exists, success;

	for (i = num = 0; input[i] != -1U; num++, i++) {
		success = TRUE;
		start = i;
		for (; input[i] != -1U; i++) {
			seq_range_array_add(&range, 32, input[i]);
			for (j = start; j < i; j++) {
				if (!seq_range_exists(&range, input[j]))
					success = FALSE;
			}
		}

		seq_range_array_invert(&range, input_min, input_max);
		for (seq = input_min; seq <= input_max; seq++) {
			for (j = start; input[j] != -1U; j++) {
				if (input[j] == seq)
					break;
			}
			old_exists = input[j] != -1U;
			if (seq_range_exists(&range, seq) == old_exists)
				success = FALSE;
		}
		test_out(t_strdup_printf("seq_range_array_invert(%u)", num),
			 success);
		array_free(&range);
	}
}

struct str_sanitize_input {
	const char *str;
	unsigned int max_len;
};
static void test_str_sanitize(void)
{
	static struct str_sanitize_input input[] = {
		{ NULL, 2 },
		{ "", 2 },
		{ "a", 2 },
		{ "ab", 2 },
		{ "abc", 2 },
		{ "abcd", 3 },
		{ "abcde", 4 }
	};
	static const char *output[] = {
		NULL,
		"",
		"a",
		"ab",
		"...",
		"...",
		"a..."
	};
	const char *str;
	unsigned int i;
	bool success;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		str = str_sanitize(input[i].str, input[i].max_len);
		success = null_strcmp(output[i], str) == 0;
		test_out(t_strdup_printf("str_sanitize(%d)", i), success);
	}
}

struct test_message_date_output {
	time_t time;
	int tz_offset;
	bool ret;
};

struct test_utc_mktime_input {
	int year, month, day, hour, min, sec;
};

static void test_utc_mktime(void)
{
	static struct test_utc_mktime_input input[] = {
#ifdef TIME_T_SIGNED
		{ 1969, 12, 31, 23, 59, 59 },
		{ 1901, 12, 13, 20, 45, 53 },
#endif
#if TIME_T_MAX_BITS > 32
		{ 2106, 2, 7, 6, 28, 15 },
#endif
		{ 2007, 11, 7, 1, 7, 20 },
		{ 1970, 1, 1, 0, 0, 0 },
		{ 2038, 1, 19, 3, 14, 7 }
	};
	static time_t output[] = {
#ifdef TIME_T_SIGNED
		-1,
		-2147483647,
#endif
#if TIME_T_MAX_BITS > 32
		4294967295,
#endif
		1194397640,
		0,
		2147483647
	};
	struct tm tm;
	unsigned int i;
	time_t t;
	bool success;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		memset(&tm, 0, sizeof(tm));
		tm.tm_year = input[i].year - 1900;
		tm.tm_mon = input[i].month - 1;
		tm.tm_mday = input[i].day;
		tm.tm_hour = input[i].hour;
		tm.tm_min = input[i].min;
		tm.tm_sec = input[i].sec;

		t = utc_mktime(&tm);
		success = t == output[i];
		test_out_reason(t_strdup_printf("utc_mktime(%d)", i), success,
				success ? NULL : t_strdup_printf("%ld != %ld",
						     (long)t, (long)output[i]));
	}
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_aqueue,
		test_base64_encode,
		test_base64_decode,
		test_bsearch_insert_pos,
		test_mempool_alloconly,
		test_priorityq,
		test_seq_range_array,
		test_str_sanitize,
		test_utc_mktime,

		test_istreams
	};
	unsigned int i;

	test_init();
	for (i = 0; i < N_ELEMENTS(test_functions); i++) {
		T_FRAME(
			test_functions[i]();
		);
	}
	return test_deinit();
}
