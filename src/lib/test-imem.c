/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

struct test_struct {
	uint32_t num[10];
};

static void test_imem_alloc(void)
{
	struct test_struct ab, bc, cd, de;

	test_begin("imem allocs");

	memset(ab.num, 0xab, sizeof(ab.num));
	memset(bc.num, 0xbc, sizeof(bc.num));
	memset(cd.num, 0xcd, sizeof(cd.num));
	memset(de.num, 0xde, sizeof(de.num));

	/* regular alloc */
	struct test_struct *s1 = i_new(struct test_struct, 2);
	struct test_struct *s2 = i_malloc(sizeof(struct test_struct) * 2);
	s1[0] = ab; s2[0] = ab;
	s1[1] = bc; s2[1] = bc;
	test_assert(memcmp(s1, s2, sizeof(struct test_struct) * 2) == 0);

	/* realloc */
	s1 = i_realloc_type(s1, struct test_struct, 2, 4);
	s2 = i_realloc(s2, sizeof(struct test_struct) * 2,
		       sizeof(struct test_struct) * 4);
	s1[2] = cd; s2[2] = cd;
	s1[3] = de; s2[3] = de;
	test_assert(memcmp(&s1[0], &ab, sizeof(ab)) == 0);
	test_assert(memcmp(&s1[1], &bc, sizeof(bc)) == 0);
	test_assert(memcmp(&s1[2], &cd, sizeof(cd)) == 0);
	test_assert(memcmp(&s1[3], &de, sizeof(de)) == 0);
	test_assert(memcmp(s1, s2, sizeof(struct test_struct) * 4) == 0);

	/* freeing realloced memory */
	i_free(s1);
	i_free(s2);
	test_assert(s1 == NULL);
	test_assert(s2 == NULL);

	/* allcating new memory with realloc */
	s1 = i_realloc_type(NULL, struct test_struct, 0, 2);
	s2 = i_realloc(NULL, 0, sizeof(struct test_struct) * 2);
	s1[0] = ab; s2[0] = ab;
	s1[1] = bc; s2[1] = bc;
	test_assert(memcmp(s1, s2, sizeof(struct test_struct) * 2) == 0);

	i_free(s1);
	i_free(s2);

	test_end();
}

void test_imem(void)
{
	test_imem_alloc();
}
