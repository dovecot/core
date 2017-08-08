/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_transaction_update_modseq,
		NULL
	};
	return test_run(test_functions);
}
