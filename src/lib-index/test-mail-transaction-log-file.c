/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#define TEST_LOG_VERSION MAIL_TRANSACTION_LOG_VERSION_FULL(1, 3)

#define INITIAL_MODSEQ 100

struct update_modseq_test {
	enum mail_transaction_type type;
	unsigned int version;
#define NOUPDATE (INITIAL_MODSEQ)
#define UPDATE (INITIAL_MODSEQ+1)
	uint64_t expected_modseq;
	unsigned int count;
	union {
		const struct mail_transaction_flag_update *flag_update;
		const struct mail_transaction_modseq_update *modseq_update;
	} v;
} update_modseq_tests[] = {
	/* expunges: increase modseq */
	{ MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT | MAIL_TRANSACTION_EXTERNAL, TEST_LOG_VERSION, UPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXPUNGE_PROT | MAIL_TRANSACTION_EXTERNAL, TEST_LOG_VERSION, UPDATE, 1, { } },
	/* expunges: don't increase modseq */
	{ MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXPUNGE_PROT, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXTERNAL, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXTERNAL, TEST_LOG_VERSION, NOUPDATE, 1, { } },

	/* flag changes: don't increase modseq */
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = 0 }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_BACKEND }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .remove_flags = MAIL_INDEX_MAIL_FLAG_BACKEND }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_DIRTY }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .remove_flags = MAIL_INDEX_MAIL_FLAG_DIRTY }
		}
	} },
	/* flag changes: increase modseq */
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_SEEN }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .remove_flags = MAIL_SEEN }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_SEEN | MAIL_INDEX_MAIL_FLAG_BACKEND }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_SEEN | MAIL_INDEX_MAIL_FLAG_DIRTY }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .remove_flags = MAIL_SEEN | MAIL_INDEX_MAIL_FLAG_BACKEND }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .remove_flags = MAIL_SEEN | MAIL_INDEX_MAIL_FLAG_DIRTY }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 2, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_DIRTY },
			{ .uid1 = 3, .uid2 = 4, .add_flags = MAIL_SEEN }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = 0, .modseq_inc_flag = 1 }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, TEST_LOG_VERSION, UPDATE, 2, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_DIRTY },
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_DIRTY, .modseq_inc_flag = 1 }
		}
	} },
	/* flag changes: increase modseq with old version */
	{ MAIL_TRANSACTION_FLAG_UPDATE, MAIL_TRANSACTION_LOG_VERSION_FULL(1, 2), UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_BACKEND }
		}
	} },
	{ MAIL_TRANSACTION_FLAG_UPDATE, MAIL_TRANSACTION_LOG_VERSION_FULL(1, 2), UPDATE, 1, {
		.flag_update = (const struct mail_transaction_flag_update[]) {
			{ .uid1 = 1, .uid2 = 2, .add_flags = MAIL_INDEX_MAIL_FLAG_DIRTY }
		}
	} },
	/* modseq updates: don't increase modseq */
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 50, .modseq_high32 = 0 }
		}
	} },
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 100, .modseq_high32 = 0 }
		}
	} },
	/* modseq updates: increase modseq */
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, 500, 1, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 500, .modseq_high32 = 0 }
		}
	} },
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, 500, 2, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 50, .modseq_high32 = 0 },
			{ .uid = 1, .modseq_low32 = 500, .modseq_high32 = 0 }
		}
	} },
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, 500, 1, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 500, .modseq_high32 = 0 },
			{ .uid = 1, .modseq_low32 = 200, .modseq_high32 = 0 }
		}
	} },
	{ MAIL_TRANSACTION_MODSEQ_UPDATE, TEST_LOG_VERSION, (uint64_t)4294967346, 1, {
		.modseq_update = (const struct mail_transaction_modseq_update[]) {
			{ .uid = 1, .modseq_low32 = 50, .modseq_high32 = 1 }
		}
	} },

	/* appends, keyword changes, attribute changes: increase modseq */
	{ MAIL_TRANSACTION_APPEND, TEST_LOG_VERSION, UPDATE, 1, { } },
	{ MAIL_TRANSACTION_KEYWORD_UPDATE, TEST_LOG_VERSION, UPDATE, 1, { } },
	{ MAIL_TRANSACTION_KEYWORD_RESET, TEST_LOG_VERSION, UPDATE, 1, { } },
	{ MAIL_TRANSACTION_ATTRIBUTE_UPDATE, TEST_LOG_VERSION, UPDATE, 1, { } },

	/* others: don't increase modseq */
	{ MAIL_TRANSACTION_HEADER_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_HEADER_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_INTRO, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_RESET, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_HDR_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_REC_UPDATE, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_ATOMIC_INC, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_EXT_HDR_UPDATE32, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_INDEX_DELETED, TEST_LOG_VERSION, NOUPDATE, 1, { } },
	{ MAIL_TRANSACTION_INDEX_UNDELETED, TEST_LOG_VERSION, NOUPDATE, 1, { } },
};

static size_t update_modseq_test_get_size(const struct update_modseq_test *test)
{
	enum mail_transaction_type type =
		test->type & MAIL_TRANSACTION_TYPE_MASK;

	if (type == (MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT))
		type = MAIL_TRANSACTION_EXPUNGE;
	if (type == (MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXPUNGE_PROT))
		type = MAIL_TRANSACTION_EXPUNGE_GUID;

	switch (type) {
	case MAIL_TRANSACTION_EXPUNGE:
		return sizeof(struct mail_transaction_expunge);
	case MAIL_TRANSACTION_EXPUNGE_GUID:
		return sizeof(struct mail_transaction_expunge_guid);
	case MAIL_TRANSACTION_APPEND:
		return sizeof(struct mail_index_record);
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
		return sizeof(struct mail_transaction_keyword_update);
	case MAIL_TRANSACTION_KEYWORD_RESET:
		return sizeof(struct mail_transaction_keyword_reset);
	case MAIL_TRANSACTION_ATTRIBUTE_UPDATE:
		return 4;
	case MAIL_TRANSACTION_FLAG_UPDATE:
		return sizeof(struct mail_transaction_flag_update);
	case MAIL_TRANSACTION_MODSEQ_UPDATE:
		return sizeof(struct mail_transaction_modseq_update);
	case MAIL_TRANSACTION_HEADER_UPDATE:
	case MAIL_TRANSACTION_EXT_INTRO:
	case MAIL_TRANSACTION_EXT_RESET:
	case MAIL_TRANSACTION_EXT_HDR_UPDATE:
	case MAIL_TRANSACTION_EXT_REC_UPDATE:
	case MAIL_TRANSACTION_EXT_ATOMIC_INC:
	case MAIL_TRANSACTION_EXT_HDR_UPDATE32:
	case MAIL_TRANSACTION_INDEX_DELETED:
	case MAIL_TRANSACTION_INDEX_UNDELETED:
		return 4;
	case MAIL_TRANSACTION_TYPE_MASK:
	case MAIL_TRANSACTION_BOUNDARY:
	case MAIL_TRANSACTION_EXPUNGE_PROT:
	case MAIL_TRANSACTION_EXTERNAL:
	case MAIL_TRANSACTION_SYNC:
		break;
	}
	i_unreached();
}

static void test_mail_transaction_update_modseq(void)
{
	struct mail_transaction_header hdr;
	unsigned char tempbuf[1024] = { 0 };

	test_begin("mail_transaction_update_modseq()");
	for (unsigned int i = 0; i < N_ELEMENTS(update_modseq_tests); i++) {
		const struct update_modseq_test *test = &update_modseq_tests[i];
		const void *data = test->v.flag_update;
		uint64_t cur_modseq = INITIAL_MODSEQ;

		if (data == NULL)
			data = tempbuf;

		hdr.type = test->type;
		hdr.size = sizeof(hdr) + update_modseq_test_get_size(test) * test->count;
		hdr.size = mail_index_uint32_to_offset(hdr.size);
		mail_transaction_update_modseq(&hdr, data, &cur_modseq, test->version);
		test_assert_idx(cur_modseq >= INITIAL_MODSEQ, i);
		test_assert_idx(test->expected_modseq == cur_modseq, i);
	}
	test_end();
}

static struct mail_index *test_mail_index_open(void)
{
	struct mail_index *index = mail_index_alloc(NULL, NULL, "test.dovecot.index");
	test_assert(mail_index_open_or_create(index, MAIL_INDEX_OPEN_FLAG_CREATE) == 0);
	struct mail_index_view *view = mail_index_view_open(index);

	struct mail_index_transaction *trans =
		mail_index_transaction_begin(view, 0);
	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	return index;
}

static void test_mail_transaction_log_file_modseq_offsets(void)
{
	test_begin("mail_transaction_log_file_get_modseq_next_offset() and _get_highest_modseq_at()");

	struct mail_index *index = test_mail_index_open();
	struct mail_transaction_log_file *file = index->log->head;

	const unsigned int max_modseq = LOG_FILE_MODSEQ_CACHE_SIZE+2;
	uoff_t modseq_next_offset[max_modseq+1];
	uoff_t modseq_alt_next_offset[max_modseq+1];

	/* start with modseq=2, because modseq=1 is the initial state */
	modseq_next_offset[1] = sizeof(struct mail_transaction_log_header);
	modseq_alt_next_offset[1] = sizeof(struct mail_transaction_log_header);
	for (uint64_t modseq = 2; modseq <= max_modseq; modseq++) {
		uint32_t seq;

		struct mail_index_view *view = mail_index_view_open(index);
		struct mail_index_transaction *trans =
			mail_index_transaction_begin(view, 0);
		mail_index_append(trans, modseq, &seq);
		test_assert(mail_index_transaction_commit(&trans) == 0);
		modseq_next_offset[modseq] = file->sync_offset;
		mail_index_view_close(&view);

		/* add a non-modseq updating change */
		view = mail_index_view_open(index);
		trans = mail_index_transaction_begin(view, 0);
		mail_index_update_flags(trans, seq, MODIFY_ADD,
			(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
		test_assert(mail_index_transaction_commit(&trans) == 0);
		mail_index_view_close(&view);
		modseq_alt_next_offset[modseq] = file->sync_offset;
	}

	/* mail_transaction_log_file_get_highest_modseq_at() is simultaneously
	   tested and it can also add offsets to cache. The difference is that
	   it adds the highest possible offset, while
	   mail_transaction_log_file_get_modseq_next_offset() adds the lowest
	   possible offset. So we'll need to allow both. */
#define MODSEQ_MATCH(modseq, next_offset) \
	((next_offset) == modseq_next_offset[modseq] || \
	 (next_offset) == modseq_alt_next_offset[modseq])

	/* 1) mail_transaction_log_file_get_modseq_next_offset() tests */
	uint64_t modseq;
	uoff_t next_offset;
	/* initial_modseq fast path */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 1, &next_offset) == 0);
	test_assert(next_offset == modseq_next_offset[1]);
	/* sync_highest_modseq fast path - it skips to sync_offset instead of
	   using exactly the same max_modseq */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, max_modseq, &next_offset) == 0);
	test_assert(next_offset == file->sync_offset);
	test_assert(next_offset != modseq_next_offset[max_modseq]);
	/* update the offset for the random tests */
	modseq_next_offset[max_modseq] = file->sync_offset;
	/* add to cache */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 2, &next_offset) == 0);
	test_assert(MODSEQ_MATCH(2, next_offset));
	/* get it from cache */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 2, &next_offset) == 0);
	test_assert(MODSEQ_MATCH(2, next_offset));
	/* get next value from cache */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 3, &next_offset) == 0);
	test_assert(MODSEQ_MATCH(3, next_offset));
	/* get previous value from cache again */
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 2, &next_offset) == 0);
	test_assert(MODSEQ_MATCH(2, next_offset));
	/* do some random testing with cache */
	for (unsigned int i = 0; i < LOG_FILE_MODSEQ_CACHE_SIZE*10; i++) {
		modseq = i_rand_minmax(1, max_modseq);
		test_assert(mail_transaction_log_file_get_modseq_next_offset(file, modseq, &next_offset) == 0);
		test_assert(MODSEQ_MATCH(modseq, next_offset));
	}
	/* go through all modseqs - do this after randomness testing or
	   modseq_alt_next_offset[] matching isn't triggered */
	for (modseq = 1; modseq <= max_modseq; modseq++) {
		test_assert(mail_transaction_log_file_get_modseq_next_offset(file, modseq, &next_offset) == 0);
		test_assert(MODSEQ_MATCH(modseq, next_offset));
	}

	/* 2) mail_transaction_log_file_get_highest_modseq_at() tests */
	uint64_t modseq_at;
	const char *error;
	/* initial_offset */
	test_assert(mail_transaction_log_file_get_highest_modseq_at(file, modseq_next_offset[1], &modseq, &error) == 0);
	test_assert(modseq == 1);
	/* sync_offset fast path */
	test_assert(mail_transaction_log_file_get_highest_modseq_at(file, file->sync_offset, &modseq, &error) == 0);
	test_assert(modseq == max_modseq);
	/* do some random testing with cache */
	for (unsigned int i = 0; i < LOG_FILE_MODSEQ_CACHE_SIZE*10; i++) {
		modseq = i_rand_minmax(1, max_modseq);
		test_assert(mail_transaction_log_file_get_highest_modseq_at(file, modseq_next_offset[modseq], &modseq_at, &error) == 0);
		test_assert(modseq_at == modseq);
		test_assert(mail_transaction_log_file_get_highest_modseq_at(file, modseq_alt_next_offset[modseq], &modseq_at, &error) == 0);
		test_assert(modseq_at == modseq);
	}
	/* go through all modseqs - do this after randomness testing or
	   modseq_alt_next_offset[] matching isn't triggered */
	for (modseq = 1; modseq <= max_modseq; modseq++) {
		test_assert(mail_transaction_log_file_get_highest_modseq_at(file, modseq_next_offset[modseq], &modseq_at, &error) == 0);
		test_assert(modseq_at == modseq);
	}

	mail_index_close(index);
	mail_index_free(&index);
	test_end();
}

static void
test_mail_transaction_log_file_get_modseq_next_offset_inconsistency(void)
{
	test_begin("mail_transaction_log_file_get_modseq_next_offset() inconsistency");

	struct mail_index *index = test_mail_index_open();
	struct mail_transaction_log_file *file = index->log->head;
	uint32_t seq;

	/* add modseq=2 */
	struct mail_index_view *view = mail_index_view_open(index);
	struct mail_index_transaction *trans =
		mail_index_transaction_begin(view, 0);
	mail_index_append(trans, 1, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* emulate a broken mail_index_modseq_header header */
	file->sync_highest_modseq = 3;

	uoff_t next_offset;
	test_expect_error_string("Transaction log modseq tracking is corrupted");
	test_assert(mail_transaction_log_file_get_modseq_next_offset(file, 2, &next_offset) == 0);
	test_expect_no_more_errors();
	test_assert(next_offset == file->sync_offset);

	mail_index_close(index);
	mail_index_free(&index);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_transaction_update_modseq,
		test_mail_transaction_log_file_modseq_offsets,
		test_mail_transaction_log_file_get_modseq_next_offset_inconsistency,
		NULL
	};
	ioloop_time = 1;
	return test_run(test_functions);
}
