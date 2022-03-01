/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "seq-set-builder.h"

static void test_seq_set_builder_add(void)
{
	struct seqset_builder *seq_set_builder;

	test_begin("seq set builder add");
	string_t *test_str = t_str_new(128);
	str_append(test_str, "UID COPY ");
	seq_set_builder = seqset_builder_init(test_str);
	seqset_builder_add(seq_set_builder, 1);
	seqset_builder_add(seq_set_builder, 3);
	seqset_builder_add(seq_set_builder, 6);
	seqset_builder_add(seq_set_builder, 7);
	seqset_builder_add(seq_set_builder, 8);
	seqset_builder_add(seq_set_builder, 9);
	seqset_builder_add(seq_set_builder, 10);
	seqset_builder_add(seq_set_builder, 12);
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "UID COPY 1,3,6:10,12");

	str_truncate(test_str, 0);
	seq_set_builder = seqset_builder_init(test_str);
	seqset_builder_add(seq_set_builder, 99999);
	seqset_builder_add(seq_set_builder, 100000);
	seqset_builder_add(seq_set_builder, 5);
	seqset_builder_add(seq_set_builder, 7);
	seqset_builder_add(seq_set_builder, 9);
	seqset_builder_add(seq_set_builder, 10);
	seqset_builder_add(seq_set_builder, 120);
	seqset_builder_add(seq_set_builder, 121);
	seqset_builder_add(seq_set_builder, 122);
	seqset_builder_add(seq_set_builder, 125);
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "99999:100000,5,7,9:10,120:122,125");

	str_truncate(test_str, 0);
	str_append(test_str, "UID COPY ");
	seq_set_builder = seqset_builder_init(test_str);
	seqset_builder_add(seq_set_builder, 287409);
	seqset_builder_add(seq_set_builder, 287410);
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "UID COPY 287409:287410");

	str_truncate(test_str, 0);
	str_append(test_str, "UID COPY 287409,");
	seq_set_builder = seqset_builder_init(test_str);
	seqset_builder_add(seq_set_builder, 287410);
	seqset_builder_add(seq_set_builder, 287411);
	test_assert_strcmp(str_c(test_str), "UID COPY 287409,287410:287411,");
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "UID COPY 287409,287410:287411");

	str_truncate(test_str, 0);
	seq_set_builder = seqset_builder_init(test_str);
	seqset_builder_add(seq_set_builder, 4294967289);
	seqset_builder_add(seq_set_builder, 4294967291);
	seqset_builder_add(seq_set_builder, 4294967293);
	seqset_builder_add(seq_set_builder, 4294967294);
	seqset_builder_add(seq_set_builder, 4294967295);
	test_assert_strcmp(str_c(test_str), "4294967289,4294967291,4294967293:4294967295,");
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "4294967289,4294967291,4294967293:4294967295");

	str_truncate(test_str, 0);
	str_append(test_str, ";j;,");
	seq_set_builder = seqset_builder_init(test_str);
	test_assert_strcmp(str_c(test_str), ";j;,");
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), ";j;,");

	test_end();
}

static void test_seq_set_builder_try_add(void)
{
	struct seqset_builder *seq_set_builder;

	test_begin("seq set builder try add");

	string_t *test_str = t_str_new(128);
	str_append(test_str, "UID MOVE ");

	seq_set_builder = seqset_builder_init(test_str);
	test_assert(seqset_builder_try_add(seq_set_builder, 20, 1));
	test_assert(seqset_builder_try_add(seq_set_builder, 20, 3));
	test_assert(seqset_builder_try_add(seq_set_builder, 20, 5));
	test_assert(seqset_builder_try_add(seq_set_builder, 20, 7));
	test_assert(seqset_builder_try_add(seq_set_builder, 20, 9));
	test_assert(19 == str_len(test_str));

	test_assert_strcmp(str_c(test_str), "UID MOVE 1,3,5,7,9,");

	test_assert(!seqset_builder_try_add(seq_set_builder, 20, 11));
	test_assert(str_len(test_str) <= 20);
	test_assert_strcmp(str_c(test_str), "UID MOVE 1,3,5,7,9,");

	test_assert(seqset_builder_try_add(seq_set_builder, 21, 2));
	test_assert(str_len(test_str) <= 21);
	test_assert_strcmp(str_c(test_str), "UID MOVE 1,3,5,7,9,2,");

	test_assert(!seqset_builder_try_add(seq_set_builder, 20, 15));
	test_assert(seqset_builder_try_add(seq_set_builder, 24, 13));
	test_assert(!seqset_builder_try_add(seq_set_builder, 24, 17));
	test_assert(str_len(test_str) <= 24);
	test_assert_strcmp(str_c(test_str), "UID MOVE 1,3,5,7,9,2,13,");
	seqset_builder_deinit(&seq_set_builder);

	str_truncate(test_str, 0);
	seq_set_builder = seqset_builder_init(test_str);
	test_assert(seqset_builder_try_add(seq_set_builder, 32, 4294967289));
	test_assert(seqset_builder_try_add(seq_set_builder, 32, 4294967291));
	test_assert(seqset_builder_try_add(seq_set_builder, 32, 4294967292));
	test_assert(!seqset_builder_try_add(seq_set_builder, 32, 4294967293));
	test_assert(seqset_builder_try_add(seq_set_builder, 50, 4294967293));
	test_assert(seqset_builder_try_add(seq_set_builder, 50, 4294967295));
	test_assert_strcmp(str_c(test_str), "4294967289,4294967291:4294967293,4294967295,");
	seqset_builder_deinit(&seq_set_builder);
	test_assert_strcmp(str_c(test_str), "4294967289,4294967291:4294967293,4294967295");

	test_end();
}

void test_seq_set_builder(void)
{
	test_seq_set_builder_add();
	test_seq_set_builder_try_add();
}
