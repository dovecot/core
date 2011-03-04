/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "dsync-proxy.h"
#include "test-dsync-common.h"
#include "test-common.h"

static void test_dsync_proxy_msg(void)
{
	static const char *test_keywords[] = {
		"kw1", "kw2", NULL
	};
	string_t *str;
	struct dsync_message msg_in, msg_out;
	const char *error;
	pool_t pool;

	memset(&msg_in, 0, sizeof(msg_in));
	memset(&msg_out, 0, sizeof(msg_out));

	pool = pool_alloconly_create("msg pool", 1024);
	str = t_str_new(256);
	msg_in.guid = "\t\001\r\nguid\t\001\n\r";
	msg_in.uid = (uint32_t)-1;
	msg_in.modseq = (uint64_t)-1;
	msg_in.save_date = (1U << 31)-1;

	test_begin("dsync proxy msg");

	/* no flags */
	dsync_proxy_msg_export(str, &msg_in);
	test_assert(dsync_proxy_msg_import(pool, str_c(str),
					   &msg_out, &error) == 0);
	test_assert(dsync_messages_equal(&msg_in, &msg_out));

	/* expunged flag */
	msg_in.flags = DSYNC_MAIL_FLAG_EXPUNGED;
	str_truncate(str, 0);
	dsync_proxy_msg_export(str, &msg_in);
	test_assert(dsync_proxy_msg_import(pool, str_c(str),
					   &msg_out, &error) == 0);
	test_assert(dsync_messages_equal(&msg_in, &msg_out));

	/* expunged flag and another flag */
	msg_in.flags = DSYNC_MAIL_FLAG_EXPUNGED | MAIL_DRAFT;
	str_truncate(str, 0);
	dsync_proxy_msg_export(str, &msg_in);
	test_assert(dsync_proxy_msg_import(pool, str_c(str),
					   &msg_out, &error) == 0);
	test_assert(dsync_messages_equal(&msg_in, &msg_out));

	/* all flags, some keywords */
	msg_in.flags = MAIL_FLAGS_MASK;
	msg_in.keywords = test_keywords;
	str_truncate(str, 0);
	dsync_proxy_msg_export(str, &msg_in);
	test_assert(dsync_proxy_msg_import(pool, str_c(str),
					   &msg_out, &error) == 0);
	test_assert(dsync_messages_equal(&msg_in, &msg_out));

	/* errors */
	test_assert(dsync_proxy_msg_import(pool, "0", &msg_out, &error) < 0);
	test_assert(dsync_proxy_msg_import(pool, "0\t0", &msg_out, &error) < 0);
	test_assert(dsync_proxy_msg_import(pool, "0\t0\t0", &msg_out, &error) < 0);
	test_assert(dsync_proxy_msg_import(pool, "0\t0\t0\t0", &msg_out, &error) < 0);
	test_assert(dsync_proxy_msg_import(pool, "0\t0\t0\t\\\t0", &msg_out, &error) < 0);
	test_assert(dsync_proxy_msg_import(pool, "0\t0\t0\t\\seen foo \\foo\t0", &msg_out, &error) < 0);

	/* flags */
	test_assert(dsync_proxy_msg_parse_flags(pool, "\\seen \\draft", &msg_out) == 0);
	test_assert(msg_out.flags == (MAIL_SEEN | MAIL_DRAFT));
	test_assert(dsync_proxy_msg_parse_flags(pool, "\\answered \\flagged", &msg_out) == 0);
	test_assert(msg_out.flags == (MAIL_ANSWERED | MAIL_FLAGGED));
	test_assert(dsync_proxy_msg_parse_flags(pool, "\\deleted \\recent", &msg_out) == 0);
	test_assert(msg_out.flags == (MAIL_DELETED | MAIL_RECENT));
	test_assert(dsync_proxy_msg_parse_flags(pool, "\\draft draft \\seen", &msg_out) == 0);
	test_assert(msg_out.flags == (MAIL_DRAFT | MAIL_SEEN));
	test_assert(strcasecmp(msg_out.keywords[0], "draft") == 0 && msg_out.keywords[1] == NULL);

	test_end();
	pool_unref(&pool);
}

static void test_dsync_proxy_mailbox(void)
{
	static const char *cache1 = "cache1";
	static const char *cache2 = "cache2";
	string_t *str;
	struct dsync_mailbox box_in, box_out;
	const char *error;
	pool_t pool;

	memset(&box_in, 0, sizeof(box_in));
	memset(&box_out, 0, sizeof(box_out));

	pool = pool_alloconly_create("mailbox pool", 1024);
	str = t_str_new(256);

	test_begin("dsync proxy mailbox");

	/* test \noselect mailbox */
	box_in.name = "\t\001\r\nname\t\001\n\r";
	box_in.name_sep = '/';
	box_in.flags = DSYNC_MAILBOX_FLAG_NOSELECT;
	dsync_proxy_mailbox_export(str, &box_in);
	test_assert(dsync_proxy_mailbox_import(pool, str_c(str),
					       &box_out, &error) == 0);
	test_assert(dsync_mailboxes_equal(&box_in, &box_out));

	/* real mailbox */
	i_assert(sizeof(box_in.mailbox_guid.guid) == sizeof(test_mailbox_guid1));
	memcpy(box_in.mailbox_guid.guid, test_mailbox_guid2, MAIL_GUID_128_SIZE);
	box_in.flags = 24242 & ~DSYNC_MAILBOX_FLAG_NOSELECT;
	box_in.uid_validity = 0xf74d921b;
	box_in.uid_next = 73529472;
	box_in.highest_modseq = 0x123456789abcdef0ULL;

	str_truncate(str, 0);
	dsync_proxy_mailbox_export(str, &box_in);
	test_assert(dsync_proxy_mailbox_import(pool, str_c(str),
					       &box_out, &error) == 0);
	test_assert(dsync_mailboxes_equal(&box_in, &box_out));

	/* limits */
	box_in.uid_next = (uint32_t)-1;
	box_in.highest_modseq = (uint64_t)-1;

	str_truncate(str, 0);
	dsync_proxy_mailbox_export(str, &box_in);
	test_assert(dsync_proxy_mailbox_import(pool, str_c(str),
					       &box_out, &error) == 0);
	test_assert(dsync_mailboxes_equal(&box_in, &box_out));

	/* mailbox with cache fields */
	t_array_init(&box_in.cache_fields, 10);
	array_append(&box_in.cache_fields, &cache1, 1);
	array_append(&box_in.cache_fields, &cache2, 1);

	str_truncate(str, 0);
	dsync_proxy_mailbox_export(str, &box_in);
	test_assert(dsync_proxy_mailbox_import(pool, str_c(str),
					       &box_out, &error) == 0);
	test_assert(dsync_mailboxes_equal(&box_in, &box_out));

	test_end();
	pool_unref(&pool);
}

static void test_dsync_proxy_guid(void)
{
	mailbox_guid_t guid_in, guid_out;
	string_t *str;

	test_begin("dsync proxy mailbox guid");

	str = t_str_new(128);
	memcpy(guid_in.guid, test_mailbox_guid1, sizeof(guid_in.guid));
	dsync_proxy_mailbox_guid_export(str, &guid_in);
	test_assert(dsync_proxy_mailbox_guid_import(str_c(str), &guid_out) == 0);
	test_assert(memcmp(guid_in.guid, guid_out.guid, sizeof(guid_in.guid)) == 0);

	test_assert(dsync_proxy_mailbox_guid_import("12345678901234567890123456789012", &guid_out) == 0);
	test_assert(dsync_proxy_mailbox_guid_import("1234567890123456789012345678901", &guid_out) < 0);
	test_assert(dsync_proxy_mailbox_guid_import("1234567890123456789012345678901g", &guid_out) < 0);
	test_assert(dsync_proxy_mailbox_guid_import("", &guid_out) < 0);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dsync_proxy_msg,
		test_dsync_proxy_mailbox,
		test_dsync_proxy_guid,
		NULL
	};
	return test_run(test_functions);
}
