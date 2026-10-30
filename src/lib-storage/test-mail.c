/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-dir.h"
#include "istream.h"
#include "write-full.h"
#include "str.h"
#include "master-service.h"
#include "message-size.h"
#include "message-binary-part.h"
#include "index/index-mail.h"
#include "index/mbox/istream-raw-mbox.h"
#include "test-mail-storage-common.h"
#include <fcntl.h>

static int
test_mail_save_trans(struct mailbox_transaction_context *trans,
		     struct istream *input)
{
	struct mail_save_context *save_ctx;
	int ret;

	save_ctx = mailbox_save_alloc(trans);
	if (mailbox_save_begin(&save_ctx, input) < 0)
		return -1;
	do {
		if (mailbox_save_continue(save_ctx) < 0) {
			mailbox_save_cancel(&save_ctx);
			return -1;
		}
	} while ((ret = i_stream_read(input)) > 0);
	i_assert(ret == -1);
	i_assert(input->stream_errno == 0);

	return mailbox_save_finish(&save_ctx);
}

static void test_mail_save(struct mailbox *box, const char *mail_input)
{
	struct mailbox_transaction_context *trans;
	struct istream *input;
	int ret;

	input = i_stream_create_from_data(mail_input, strlen(mail_input));
	trans = mailbox_transaction_begin(box,
			MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	ret = test_mail_save_trans(trans, input);
	i_stream_unref(&input);
	if (ret < 0)
		mailbox_transaction_rollback(&trans);
	else
		ret = mailbox_transaction_commit(&trans);
	if (ret < 0) {
		i_fatal("Failed to save mail: %s",
			mailbox_get_last_internal_error(box, NULL));
	}
	if (mailbox_sync(box, 0) < 0)
		i_fatal("Failed to sync mailbox: %s",
			mailbox_get_last_internal_error(box, NULL));
}

static void test_mail_remove_keywords(struct mailbox *box)
{
	struct mailbox_transaction_context *trans;
	const char *keywords[] = { NULL };
	struct mail_keywords *kw;
	struct mail *mail;

	trans = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);
	if (mailbox_keywords_create(box, keywords, &kw) < 0)
		i_fatal("mailbox_keywords_create() failed: %s",
			mailbox_get_last_internal_error(box, NULL));
	mail_update_keywords(mail, MODIFY_REPLACE, kw);
	mailbox_keywords_unref(&kw);
	mail_free(&mail);
	if (mailbox_transaction_commit(&trans) < 0) {
		i_fatal("Failed to update flags: %s",
			mailbox_get_last_internal_error(box, NULL));
	}
	if (mailbox_sync(box, 0) < 0)
		i_fatal("Failed to sync mailbox: %s",
			mailbox_get_last_internal_error(box, NULL));
}

static struct mailbox_header_lookup_ctx *
test_mail_fetch_get_random_headers(struct mailbox *box)
{
	ARRAY_TYPE(const_string) headers_arr;
	const char *potential_headers[] = {
		"From", "To", "Subject", "Nonexistent",
	};

	t_array_init(&headers_arr, N_ELEMENTS(potential_headers)+1);
	do {
		for (unsigned int i = 0; i < N_ELEMENTS(potential_headers); i++) {
			if (i_rand_limit(2) == 0)
				array_push_back(&headers_arr, &potential_headers[i]);
		}
	} while (array_count(&headers_arr) == 0);

	array_append_zero(&headers_arr);
	return mailbox_header_lookup_init(box, array_idx(&headers_arr, 0));
}

static void
test_mail_fetch_field(struct mail *mail, enum mail_fetch_field field)
{
	struct message_part *parts;
	struct message_size hdr_size, body_size;
	struct istream *input;
	const char *str;
	time_t t;
	uoff_t size;
	struct mail_binary_properties bprops;
	int tz, ret = 0;

	e_debug(test_event, "field=0x%x", field);
	switch (field) {
	case MAIL_FETCH_FLAGS:
		(void)mail_get_flags(mail);
		(void)mail_get_keywords(mail);
		break;
	case MAIL_FETCH_MESSAGE_PARTS:
		ret = mail_get_parts(mail, &parts);
		break;
	case MAIL_FETCH_STREAM_HEADER:
		ret = mail_get_hdr_stream(mail,
			i_rand_limit(2) == 0 ? &hdr_size : NULL, &input);
		break;
	case MAIL_FETCH_STREAM_BODY:
		ret = mail_get_stream(mail,
			i_rand_limit(2) == 0 ? &hdr_size : NULL,
			i_rand_limit(2) == 0 ? &body_size : NULL, &input);
		break;
	case MAIL_FETCH_DATE:
		ret = mail_get_date(mail, &t, &tz);
		break;
	case MAIL_FETCH_RECEIVED_DATE:
		ret = mail_get_received_date(mail, &t);
		break;
	case MAIL_FETCH_SAVE_DATE:
		ret = mail_get_save_date(mail, &t);
		break;
	case MAIL_FETCH_PHYSICAL_SIZE:
		ret = mail_get_physical_size(mail, &size);
		break;
	case MAIL_FETCH_VIRTUAL_SIZE:
		ret = mail_get_virtual_size(mail, &size);
		break;
	case MAIL_FETCH_NUL_STATE:
		/* nothing to do */
		break;
	case MAIL_FETCH_STREAM_BINARY:
		if ((ret = mail_get_parts(mail, &parts)) < 0)
			break;

		if (i_rand_limit(2) == 0) {
			ret = mail_get_binary_stream(mail, parts,
						     i_rand_limit(2) == 0,
						     &bprops, &input);
			if (ret == 0)
				i_stream_unref(&input);
		} else {
			ret = mail_get_binary_properties(mail, parts,
							 i_rand_limit(2) == 0,
							 &bprops);
		}
		break;
	case MAIL_FETCH_IMAP_BODY:
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
	case MAIL_FETCH_IMAP_ENVELOPE:
	case MAIL_FETCH_FROM_ENVELOPE:
	case MAIL_FETCH_HEADER_MD5:
	case MAIL_FETCH_STORAGE_ID:
	case MAIL_FETCH_UIDL_BACKEND:
	case MAIL_FETCH_MAILBOX_NAME:
	case MAIL_FETCH_SEARCH_RELEVANCY:
	case MAIL_FETCH_GUID:
	case MAIL_FETCH_POP3_ORDER:
	case MAIL_FETCH_REFCOUNT:
	case MAIL_FETCH_BODY_SNIPPET:
	case MAIL_FETCH_REFCOUNT_ID:
		ret = mail_get_special(mail, field, &str);
		break;
	}
	if (ret < 0) {
		const char *errstr;
		enum mail_error error;

		errstr = mailbox_get_last_internal_error(mail->box, &error);
		if (error != MAIL_ERROR_LOOKUP_ABORTED)
			i_error("Failed to fetch field 0x%x: %s", field, errstr);
	}
}

static void
test_mail_fetch_headers(struct mail *mail,
			struct mailbox_header_lookup_ctx *headers)
{
	struct istream *input;

	e_debug(test_event, "header fields");
	if (mail_get_header_stream(mail, headers, &input) < 0) {
		const char *errstr;
		enum mail_error error;

		errstr = mailbox_get_last_internal_error(mail->box, &error);
		if (error != MAIL_ERROR_LOOKUP_ABORTED)
			i_error("Failed to fetch headers: %s", errstr);
		return;
	}
	while (i_stream_read(input) > 0)
		i_stream_skip(input, i_stream_get_data_size(input));
}

static void test_mail_random_fetch(struct mailbox *box, uint32_t seq)
{
	const enum mail_fetch_field potential_fields[] = {
		MAIL_FETCH_FLAGS,
		MAIL_FETCH_MESSAGE_PARTS,
		MAIL_FETCH_STREAM_HEADER,
		MAIL_FETCH_STREAM_BODY,
		MAIL_FETCH_DATE,
		MAIL_FETCH_RECEIVED_DATE,
		MAIL_FETCH_SAVE_DATE,
		MAIL_FETCH_PHYSICAL_SIZE,
		MAIL_FETCH_VIRTUAL_SIZE,
		MAIL_FETCH_NUL_STATE,
		MAIL_FETCH_STREAM_BINARY,
		MAIL_FETCH_IMAP_BODY,
		MAIL_FETCH_IMAP_BODYSTRUCTURE,
		MAIL_FETCH_IMAP_ENVELOPE,
		MAIL_FETCH_FROM_ENVELOPE,
		MAIL_FETCH_HEADER_MD5,
		MAIL_FETCH_STORAGE_ID,
		MAIL_FETCH_UIDL_BACKEND,
		MAIL_FETCH_MAILBOX_NAME,
		MAIL_FETCH_SEARCH_RELEVANCY,
		MAIL_FETCH_GUID,
		MAIL_FETCH_POP3_ORDER,
		MAIL_FETCH_REFCOUNT,
		MAIL_FETCH_BODY_SNIPPET,
		MAIL_FETCH_REFCOUNT_ID,
	};
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	enum mail_fetch_field wanted_fields = 0;
	struct mailbox_header_lookup_ctx *headers = NULL;

	if (i_rand_limit(2) == 0)
		wanted_fields = i_rand();
	if (i_rand_limit(2) == 0)
		headers = test_mail_fetch_get_random_headers(box);
	trans = mailbox_transaction_begin(box, 0, __func__);
	e_debug(test_event, "wanted_fields=%u wanted_headers=%p", wanted_fields, headers);
	mail = mail_alloc(trans, wanted_fields, headers);
	mailbox_header_lookup_unref(&headers);
	mail_set_seq(mail, seq);

	for (unsigned int i = 0; i < 5; i++) {
		unsigned int fetch_field_idx =
			i_rand_limit(N_ELEMENTS(potential_fields) + 1);

		if (i_rand_limit(3) == 0)
			mail->lookup_abort = 1+i_rand_limit(MAIL_LOOKUP_ABORT_NOT_IN_CACHE_START_CACHING);
		if (fetch_field_idx < N_ELEMENTS(potential_fields)) {
			test_mail_fetch_field(mail,
				potential_fields[fetch_field_idx]);
		} else {
			headers = test_mail_fetch_get_random_headers(box);
			test_mail_fetch_headers(mail, headers);
			mailbox_header_lookup_unref(&headers);
		}
		mail->lookup_abort = MAIL_LOOKUP_ABORT_NEVER;
	}
	mail_free(&mail);
	if (mailbox_transaction_commit(&trans) < 0) {
		i_fatal("Failed to commit transaction: %s",
			mailbox_get_last_internal_error(box, NULL));
	}
}

static void test_mail_random_access(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *const potential_never_cache_fields[] = {
		"",
		"flags",
		"mime.parts",
		"imap.body",
		"imap.bodystructure",
	};
	unsigned int never_cache_field_idx =
		i_rand_limit(N_ELEMENTS(potential_never_cache_fields));
	const char *never_cache_fields =
		potential_never_cache_fields[never_cache_field_idx];
	const char *const extra_input[] = {
		"mail_attachment_detection_options=add-flags",
		t_strconcat("mail_never_cache_fields=",
			    never_cache_fields, NULL),
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = extra_input,
	};
	struct mailbox *box;

	test_begin("mail");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);
	e_debug(test_event, "mail_never_cache_fields=%s", never_cache_fields);
	for (unsigned int i = 0; i < 20; i++) {
		box = mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
		if (mailbox_open(box) < 0)
			i_fatal("Failed to open mailbox: %s",
				mailbox_get_last_internal_error(box, NULL));
		test_mail_save(box,
			       "From: <test1@example.com>\n"
			       "To: <test1-dest@example.com>\n"
			       "Subject: test subject\n"
			       "\n"
			       "test body\n");
		test_mail_remove_keywords(box);
		e_debug(test_event, "--------------");
		for (unsigned int j = 0; j < 3; j++)
			test_mail_random_fetch(box, 1);
		if (mailbox_delete(box) < 0)
			i_fatal("Failed to delete mailbox: %s",
				mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
	}
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_attachment_flags_during_header_fetch(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *const extra_input[] = {
		"mail_attachment_detection_options=add-flags",
		"mail_always_cache_fields=flags",
		"mail_cache_fields=flags",
		"mail_never_cache_fields=mime.parts",
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = extra_input,
	};

	test_begin("mail attachment flags during header fetch");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

#define TEST_HDR_FROM "From: <test1@example.com>\r\n"
	test_mail_save(box,
		       TEST_HDR_FROM
		       "\r\n"
		       "test body\n");
	/* Remove the $HasNoAttachment keyword */
	test_mail_remove_keywords(box);

	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);

	const char *from_headers[] = { "From", NULL };
	struct mailbox_header_lookup_ctx *headers =
		mailbox_header_lookup_init(box, from_headers);

	struct istream *input;
	const unsigned char *data;
	size_t size;
	test_assert(mail_get_header_stream(mail, headers, &input) == 0);
	test_assert(i_stream_read_more(input, &data, &size) == 1);
	/* TEST_HDR_FROM */
	test_assert(size == strlen(TEST_HDR_FROM) &&
		    memcmp(data, TEST_HDR_FROM, strlen(TEST_HDR_FROM)) == 0);
	i_stream_skip(input, size);
	test_assert(i_stream_read_more(input, &data, &size) == 1);
	test_assert(size == 2 && memcmp(data, "\r\n", 2) == 0);
	i_stream_skip(input, size);
	test_assert(i_stream_read_more(input, &data, &size) == -1);

	mailbox_header_lookup_unref(&headers);
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_bodystructure_reparsing(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *const extra_input[] = {
		"mail_attachment_detection_options=add-flags",
		"mail_never_cache_fields=flags",
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = extra_input,
	};
	const char *value;

	test_begin("mail bodystructure reparsing");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

	test_mail_save(box,
		       "From: <test1@example.com>\r\n"
		       "\r\n"
		       "test body\n");

	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, MAIL_FETCH_IMAP_BODYSTRUCTURE, NULL);
	mail_set_seq(mail, 1);

	/* start parsing header */
	test_assert(mail_get_first_header(mail, "From", &value) == 1);
	/* fetching snippet triggers re-parsing the header */
	test_assert(mail_get_special(mail, MAIL_FETCH_BODY_SNIPPET, &value) == 0);

	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_bodystructure_corruption_reparsing(void)
{
	struct test_mail_storage_ctx *ctx;
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
	};
	const char *value;

	test_begin("bodystructure corruption reparsing");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

	test_mail_save(box,
		       "From: <test1@example.com>\r\n"
		       "\r\n"
		       "test body\n");

	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);

	test_assert(mail_get_special(mail, MAIL_FETCH_IMAP_BODY, &value) == 0);
	test_expect_error_string("Mailbox INBOX: UID 1: Deleting corrupted cache record: Broken MIME parts in mailbox INBOX: test");
	mail_set_cache_corrupted(mail, MAIL_FETCH_MESSAGE_PARTS, "test");
	test_expect_no_more_errors();
	test_assert(mail_get_special(mail, MAIL_FETCH_IMAP_BODYSTRUCTURE, &value) == 0);

	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_binary_size_corruption_recompute(void)
{
	struct test_mail_storage_ctx *ctx;
	const struct test_mail_storage_settings set = {
		.driver = "sdbox",
	};
	struct message_part *parts;
	struct mail_binary_properties bprops, bprops2;

	test_begin("BINARY.SIZE corruption recompute");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

	test_mail_save(box,
		       "MIME-Version: 1.0\r\n"
		       "Content-Type: text/plain\r\n"
		       "Content-Transfer-Encoding: base64\r\n"
		       "\r\n"
		       "dGVzdCBib2R5\r\n");

	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);

	test_assert(mail_get_parts(mail, &parts) == 0);
	test_assert(mail_get_binary_properties(mail, parts, TRUE, &bprops) == 0);
	test_assert(bprops.converted);

	/* Add a duplicate of the binary part, so the sizes don't match the
	   MIME parts anymore. */
	struct index_mail *imail = INDEX_MAIL(mail);
	struct message_binary_part *dup =
		p_new(imail->mail.data_pool, struct message_binary_part, 1);
	*dup = *imail->data.bin_parts;
	dup->next = imail->data.bin_parts;
	imail->data.bin_parts = dup;

	test_expect_error_string("Mailbox INBOX: UID 1: Deleting corrupted cache record: BINARY part sizes don't match MIME parts");
	test_assert(mail_get_binary_properties(mail, parts, TRUE, &bprops2) < 0);
	test_expect_no_more_errors();

	/* The broken binary.parts were dropped, so they are calculated again */
	test_assert(mail_get_binary_properties(mail, parts, TRUE, &bprops2) == 0);
	test_assert_cmp(bprops2.size, ==, bprops.size);
	test_assert_cmp(bprops2.lines, ==, bprops.lines);

	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_mbox_raw_istream_eof(void)
{
	const char *mbox =
		"From a@example.com Thu Nov  9 22:33:52 2001\n"
		"Subject: 1\n"
		"\n"
		"body\n";
	struct istream *input, *raw_input;
	uoff_t size;

	test_begin("mbox raw istream EOF");
	input = test_istream_create(mbox);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	/* The read that finds EOF may move the parent's buffer. Only a memory
	   checker such as valgrind or AddressSanitizer notices a stale buffer:
	   the size comes out the same. */
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(istream_raw_mbox_get_body_size(raw_input, UOFF_T_MAX,
						   &size) == 0);
	test_assert_cmp(size, ==, strlen("body"));

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_expected_size_at_eof(void)
{
	const char *mbox =
		"From a@example.com Thu Nov  9 22:33:52 2001\n"
		"Subject: 1\n"
		"Content-Length: 5\n"
		"\n"
		"body\n"
		"\n";
	struct istream *input, *raw_input;
	uoff_t size;

	test_begin("mbox raw istream expected body size at EOF");
	input = test_istream_create(mbox);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	/* Checking what follows the body reads up to EOF, which may move the
	   parent's buffer. Only a memory checker such as valgrind or
	   AddressSanitizer notices a stale buffer: the fallback read of the
	   whole body gives the same size. */
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(istream_raw_mbox_get_body_size(raw_input, strlen("body\n"),
						   &size) == 0);
	test_assert_cmp(size, ==, strlen("body\n"));

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_from_after_empty_from(void)
{
	const char *mbox =
		"From a@example.com Thu Nov  9 22:33:52 2001\n"
		"Subject: 1\n"
		"\n"
		"body\n"
		"From \n"
		"From b@example.com Thu Nov  9 22:33:52 2001\n"
		"Subject: 2\n"
		"\n"
		"body2\n";
	struct istream *input, *raw_input;
	uoff_t size;

	test_begin("mbox raw istream From_ right after an invalid one");
	input = test_istream_create(mbox);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	/* The LF right after "From " ends the invalid From_ line and begins
	   the valid one. */
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(istream_raw_mbox_get_body_size(raw_input, UOFF_T_MAX,
						   &size) == 0);
	test_assert_cmp(size, ==, strlen("body\nFrom "));
	test_assert(istream_raw_mbox_next(raw_input, UOFF_T_MAX) == 0);
	test_assert_strcmp(istream_raw_mbox_get_sender(raw_input),
			   "b@example.com");

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_crlf_from_at_buffer_end(void)
{
	const char *from1 = "From a@b Thu Nov  9 22:33:52 2001\n";
	const char *from2 = "From x Thu Nov 29 22:33:52 2001\r\n";
	const size_t buffer_size = 40;
	struct istream *input, *raw_input;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	string_t *mbox = t_str_new(256);

	/* A line without an LF fills the parent's buffer up to the CR+LF
	   and "From " of the second mail. */
	str_append(mbox, from1);
	for (size_t i = 0; i < buffer_size - strlen("\r\nFrom "); i++)
		str_append_c(mbox, 'x');
	str_append(mbox, "\r\n");
	str_append(mbox, from2);
	str_append(mbox, "Subject: 2\r\n\r\nbody2\r\n");

	test_begin("mbox raw istream CRLF From_ at buffer end");
	input = test_istream_create(str_c(mbox));
	test_istream_set_max_buffer_size(input, buffer_size);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	/* The reader holds the line until it can't get more, and then
	   consumes it except for a trailing CR, which might belong to a CR+LF.
	   The CR before "\nFrom " must not end up in the reader's hands. */
	for (unsigned int i = 0; i < 10; i++) {
		ret = i_stream_read(raw_input);
		if (ret == -1)
			break;
		data = i_stream_get_data(raw_input, &size);
		if (ret != -2 && size <= buffer_size - strlen("\r\nFrom "))
			continue;
		if (size > 0 && data[size-1] == '\r')
			size--;
		i_stream_skip(raw_input, size);
	}
	test_assert_cmp(ret, ==, -1);
	test_assert(raw_input->stream_errno == 0);
	test_assert(istream_raw_mbox_next(raw_input, UOFF_T_MAX) == 0);
	test_assert_strcmp(istream_raw_mbox_get_sender(raw_input), "x");

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_invalid_expected_size(void)
{
	const char *mbox =
		"From a@b Thu Nov  9 22:33:52 2001\n"
		"Subject: 1\n"
		"\n"
		"\n"
		"From c@d Thu Nov  9 22:33:52 2001\n"
		"Subject: 2\n"
		"\n"
		"body2\n"
		"\n"
		"From x Thu Nov  9 22:33:52 2001\n"
		"Subject: 3\n"
		"\n"
		"body3\n";
	const size_t buffer_size = 40;
	struct istream *input, *raw_input;
	uoff_t body_size;
	ssize_t ret;

	test_begin("mbox raw istream invalid expected body size");
	input = test_istream_create(mbox);
	test_istream_set_max_buffer_size(input, buffer_size);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	for (unsigned int mail = 0; mail < 2; mail++) {
		for (unsigned int i = 0;; i++) {
			ret = i_stream_read(raw_input);
			if (ret == -1)
				break;
			if (mail == 1 && i == 1) {
				/* The Content-Length is invalid. Checking it
				   moved the parent stream, so the next read
				   finds its buffer full of the end of the mail
				   and a cut-off From_ line. The end of the mail
				   has to be returned before the line can be
				   checked. */
				test_assert(istream_raw_mbox_get_body_size(
					raw_input, 3, &body_size) == 0);
				test_assert_cmp(body_size, ==, strlen("body2\n"));
				ret = i_stream_read(raw_input);
				if (ret == -1)
					break;
			}
			i_stream_skip(raw_input,
				      i_stream_get_data_size(raw_input));
		}
		i_stream_skip(raw_input, i_stream_get_data_size(raw_input));
		test_assert(istream_raw_mbox_next(raw_input, UOFF_T_MAX) == 0);
	}
	test_assert_strcmp(istream_raw_mbox_get_sender(raw_input), "x");

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_expected_size_inside_crlf(void)
{
	static const struct {
		const char *mbox;
		uoff_t expected_size;
		uoff_t body_size;
	} tests[] = {
		/* ends between the CR and LF of the blank line */
		{ "From a@b Thu Nov  9 22:33:52 2001\r\n"
		  "Subject: 1\r\n"
		  "\r\n"
		  "xxxxxxxx\r\n"
		  "\r\n"
		  "From c@d Thu Nov  9 22:33:52 2001\r\n"
		  "Subject: 2\r\n",
		  11, 10 },
		/* ends between the CR and LF of the last body line */
		{ "From a@b Thu Nov  9 22:33:52 2001\n"
		  "Subject: 1\n"
		  "\n"
		  "abc\r\n"
		  "From c@d Thu Nov  9 22:33:52 2001\n"
		  "Subject: 2\n",
		  4, 3 },
		/* includes the CR+LF of the last body line */
		{ "From a@b Thu Nov  9 22:33:52 2001\n"
		  "Subject: 1\n"
		  "\n"
		  "abc\r\n"
		  "\n"
		  "From c@d Thu Nov  9 22:33:52 2001\n"
		  "Subject: 2\n",
		  5, 5 },
	};
	struct istream *input, *raw_input;
	uoff_t size;

	test_begin("mbox raw istream expected body size inside CR+LF");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		input = test_istream_create(tests[i].mbox);
		raw_input = i_stream_create_raw_mbox(input);
		istream_raw_mbox_set_locked(raw_input);

		/* The CR belongs to the line break, so the mail ends before
		   it. */
		test_assert_idx(istream_raw_mbox_seek(raw_input, 0) == 0, i);
		test_assert_idx(istream_raw_mbox_get_body_size(raw_input,
			tests[i].expected_size, &size) == 0, i);
		test_assert_idx(size == tests[i].body_size, i);
		test_assert_idx(istream_raw_mbox_next(raw_input,
						      UOFF_T_MAX) == 0, i);
		test_assert_strcmp_idx(istream_raw_mbox_get_sender(raw_input),
				       "c@d", i);

		i_stream_unref(&raw_input);
		i_stream_unref(&input);
	}
	test_end();
}

static void test_mbox_out_of_uids(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *const extra_input[] = {
		"mail_inbox_path=%{home}/inbox",
		NULL
	};
	const struct test_mail_storage_settings set = {
		.driver = "mbox",
		.extra_input = extra_input,
	};
	struct mailbox_update update = { .min_next_uid = 4294967294U };
	struct mailbox_status status;
	const char *mail_input = "From: <test1@example.com>\n\ntest body\n";

	test_begin("mbox out of UIDs");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);
	/* make the mbox empty, but keep it existing */
	test_mail_save(box, mail_input);
	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);
	mail_expunge(mail);
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	test_assert(mailbox_sync(box, 0) == 0);

	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &status);
	uint32_t orig_uid_validity = status.uidvalidity;

	/* The next UID is past the highest usable one. Saving renumbers the
	   mbox instead of failing. The log has "Out of UIDs, renumbering them
	   in mbox" errors and "UIDVALIDITY changed" warnings from the
	   syncs. */
	test_expect_errors(3);
	test_assert(mailbox_update(box, &update) == 0);
	test_expect_no_more_errors();
	test_expect_errors(2);
	test_mail_save(box, mail_input);
	test_expect_no_more_errors();

	mailbox_get_open_status(box, STATUS_UIDNEXT | STATUS_UIDVALIDITY,
				&status);
	test_assert_cmp(status.uidnext, <, 1000);
	test_assert_cmp(status.uidvalidity, !=, orig_uid_validity);

	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_mbox_x_uid_overflow(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *mbox =
		"From a@example.com Thu Nov  9 22:33:52 2001\n"
		"X-IMAPbase: 1 2\n"
		"X-UID: 1\n"
		"Subject: 1\n"
		"\n"
		"body\n"
		"\n"
		"From b@example.com Thu Nov  9 22:33:52 2001\n"
		"X-UID: 4294967298\n"
		"Subject: 2\n"
		"\n"
		"body2\n"
		"\n";
	int fd;

	test_begin("mbox X-UID overflow");
	ctx = test_mail_storage_init();
	const char *path = t_strdup_printf("%stestuser/inbox", ctx->home_root);
	const char *const extra_input[] = {
		t_strdup_printf("mail_inbox_path=%s", path),
		NULL
	};
	const struct test_mail_storage_settings set = {
		.driver = "mbox",
		.extra_input = extra_input,
	};
	test_mail_storage_init_user(ctx, &set);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write_full(fd, mbox, strlen(mbox)) < 0)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);
	test_assert(mailbox_sync(box, 0) == 0);

	/* The X-UID doesn't fit in 32 bits. It must not wrap around to a UID
	   that looks valid, so the mail gets a new UID. */
	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 2);
	test_assert_cmp(mail->uid, ==, 3);
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);

	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_mbox_update_min_next_uid_unsynced(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *const extra_input[] = {
		"mail_inbox_path=%{home}/inbox",
		NULL
	};
	const struct test_mail_storage_settings set = {
		.driver = "mbox",
		.extra_input = extra_input,
	};
	struct mailbox_update update = { .min_next_uid = 100 };
	struct mailbox_status status;

	test_begin("mbox min_next_uid update of unsynced mailbox");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_update(box, &update) == 0);

	test_assert(mailbox_sync(box, 0) == 0);
	mailbox_get_open_status(box, STATUS_UIDNEXT | STATUS_UIDVALIDITY,
				&status);
	test_assert_cmp(status.uidvalidity, !=, 0);
	test_assert_cmp(status.uidnext, ==, 100);

	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_mbox_raw_istream_reader_holds_data(void)
{
	const char *from2 = "From c@d Thu Nov  9 22:33:52 2001\n";
	const size_t buffer_size = 35;
	struct istream *input, *raw_input;
	ssize_t ret;
	string_t *mbox = t_str_new(256);

	str_append(mbox, "From a@b Thu Nov  9 22:33:52 2001\n");
	str_append(mbox, "Subject: 1\n\n");
	for (unsigned int i = 0; i < 24; i++)
		str_append_c(mbox, 'x');
	str_append_c(mbox, '\n');
	str_append(mbox, from2);
	str_append(mbox, "Subject: 2\n\nbody2\n");

	test_begin("mbox raw istream reader holds a few bytes");
	input = test_istream_create(str_c(mbox));
	test_istream_set_max_buffer_size(input, buffer_size);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	/* The reader holds everything it has read until it gets -2. At one
	   point it holds two bytes and the buffer is full of the beginning of
	   the next From_ line, which can't be verified before the reader has
	   consumed them. */
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	for (unsigned int i = 0; i < 100; i++) {
		ret = i_stream_read(raw_input);
		if (ret == -1)
			break;
		if (ret == -2) {
			i_stream_skip(raw_input,
				      i_stream_get_data_size(raw_input));
		}
	}
	test_assert_cmp(ret, ==, -1);
	test_assert(istream_raw_mbox_next(raw_input, UOFF_T_MAX) == 0);
	test_assert_strcmp(istream_raw_mbox_get_sender(raw_input), "c@d");

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_body_size_long_from(void)
{
	const size_t buffer_size = 40;
	struct istream *input, *raw_input;
	struct message_size full_size, small_size;
	bool has_nuls;
	string_t *mbox = t_str_new(256);

	str_append(mbox, "From a@b Thu Nov  9 22:33:52 2001\n");
	str_append(mbox, "Subject: 1\n\n\nFrom ");
	for (unsigned int i = 0; i < 90; i++)
		str_append_c(mbox, 'q');
	str_append(mbox, "\nFrom c@d Thu Nov  9 22:33:52 2001\n");
	str_append(mbox, "Subject: 2\n\nbody2\n");

	test_begin("mbox raw istream body size with a long From_ line");
	input = test_istream_create(str_c(mbox));
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(message_get_body_size(raw_input, &full_size,
					  &has_nuls) == 0);
	i_stream_unref(&raw_input);
	i_stream_unref(&input);

	/* message_get_body_size() leaves one byte unconsumed and asks for
	   two, so it can't consume anything when the buffer is full. */
	input = test_istream_create(str_c(mbox));
	test_istream_set_max_buffer_size(input, buffer_size);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(message_get_body_size(raw_input, &small_size,
					  &has_nuls) == 0);
	test_assert_cmp(small_size.physical_size, ==, full_size.physical_size);

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_raw_istream_nul_after_from(void)
{
	const char *from1 = "From a@b Thu Nov  9 22:33:52 2001\n";
	const char *hdr = "Subject: 1\n\n";
	const size_t buffer_size = 40;
	struct istream *input, *raw_input;
	string_t *mbox = t_str_new(256);
	uoff_t size;

	str_append(mbox, from1);
	str_append(mbox, hdr);
	/* A From_ line that doesn't parse and is longer than the buffer, with
	   a NUL byte right after "\nFrom ". */
	str_append_data(mbox, "\nFrom \0", 7);
	for (unsigned int i = 0; i < 2 * buffer_size; i++)
		str_append_c(mbox, 'x');

	test_begin("mbox raw istream NUL after From_");
	input = test_istream_create_data(str_data(mbox), str_len(mbox));
	test_istream_set_max_buffer_size(input, buffer_size);
	raw_input = i_stream_create_raw_mbox(input);
	istream_raw_mbox_set_locked(raw_input);

	/* The NUL byte must not match the end of the "\nFrom " string. The
	   over-read is in static data, so only AddressSanitizer notices it. */
	test_assert(istream_raw_mbox_seek(raw_input, 0) == 0);
	test_assert(istream_raw_mbox_get_body_size(raw_input, UOFF_T_MAX,
						   &size) == 0);
	test_assert_cmp(size, ==, 7 + 2 * buffer_size);

	i_stream_unref(&raw_input);
	i_stream_unref(&input);
	test_end();
}

static void test_mbox_save_from_header_lines(void)
{
	/* The sender is too long for a header name, so the line has no name. */
	string_t *long_from = t_str_new(1200);
	str_append(long_from, "From ");
	for (unsigned int i = 0; i < 1100; i++)
		str_append_c(long_from, 'a');
	str_append(long_from, "@example.com Mon Jan  1 00:00:00 2024");

	const struct {
		const char *line;
		bool kept;
	} tests[] = {
		{ "From user@example.com Mon Jan  1 00:00:00 2024", FALSE },
		{ "From :x Mon Jan  1 00:00:00 2024", FALSE },
		{ str_c(long_from), FALSE },
		{ "From: a@b", TRUE },
		{ "From :a@b", TRUE },
		{ "Fromx Mon Jan  1 00:00:00 2024", TRUE },
	};
	struct test_mail_storage_ctx *ctx;
	const char *const extra_input[] = {
		"mail_inbox_path=%{home}/inbox",
		NULL
	};
	const struct test_mail_storage_settings set = {
		.driver = "mbox",
		.extra_input = extra_input,
	};
	struct mailbox_status status;
	struct istream *input;
	const unsigned char *data;
	size_t size;

	test_begin("mbox save From_ header lines");
	ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_mail_save(box, t_strdup_printf(
			"Subject: test\n%s\n\nbody\n", tests[i].line));

		/* the mail must not be split into two */
		mailbox_get_open_status(box, STATUS_MESSAGES, &status);
		test_assert_cmp_idx(status.messages, ==, i + 1, i);

		struct mailbox_transaction_context *trans =
			mailbox_transaction_begin(box, 0, __func__);
		struct mail *mail = mail_alloc(trans, 0, NULL);
		mail_set_seq(mail, i + 1);
		test_assert_idx(mail_get_hdr_stream(mail, NULL, &input) == 0, i);
		string_t *hdr = t_str_new(1200);
		while (i_stream_read_more(input, &data, &size) > 0) {
			str_append_data(hdr, data, size);
			i_stream_skip(input, size);
		}
		bool found = strstr(str_c(hdr), tests[i].line) != NULL;
		test_assert_cmp_idx(found, ==, tests[i].kept, i);
		mail_free(&mail);
		test_assert(mailbox_transaction_commit(&trans) == 0);
	}

	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_mail_set_critical(void)
{
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
	};

	struct test_mail_storage_ctx *ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);

	test_mail_save(box,
		       "From: <test1@example.com>\n"
		       "\n"
		       "test body\n");

	struct mail_private *pmail;
	enum mail_error mail_error;
	const char *last_internal_error;

	test_begin("mail_set_critical (UID)");
	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);
	mail->saving = FALSE;
	test_expect_error_string("Mailbox INBOX: UID 1: Mail Error: uid=1, "
				 "saving=false");
	mail_set_critical(mail, "Mail Error: uid=%u, saving=%s", mail->uid,
			  "false");
	test_expect_no_more_errors();
	last_internal_error = mail_get_last_internal_error(mail, &mail_error);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert_strcmp(last_internal_error,
			   "Mail Error: uid=1, saving=false");
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	test_end();

	test_begin("mail_set_critical (saving-prefix: no uid)");
	trans = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(trans, 0, NULL);
	pmail = container_of(mail, struct mail_private, mail);
	event_unref(&pmail->_event);
	mail->saving = TRUE;
	test_expect_error_string("Mailbox INBOX: Saving mail: Mail Error: "
				 "uid=0, saving=true");
	mail_set_critical(mail, "Mail Error: uid=%u, saving=%s", mail->uid,
			  "true");
	test_expect_no_more_errors();
	last_internal_error = mail_get_last_internal_error(mail, &mail_error);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert_strcmp(last_internal_error,
			   "Mail Error: uid=0, saving=true");
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	test_end();

	test_begin("mail_set_critical (saving-prefix: UID)");
	trans = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);
	pmail = container_of(mail, struct mail_private, mail);
	event_unref(&pmail->_event);
	mail->saving = TRUE;
	test_expect_error_string("Mailbox INBOX: Saving mail UID 1: "
				 "Mail Error: uid=1, saving=true");
	mail_set_critical(mail, "Mail Error: uid=%u, saving=%s", mail->uid,
			  "true");
	test_expect_no_more_errors();
	last_internal_error = mail_get_last_internal_error(mail, &mail_error);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert_strcmp(last_internal_error,
			   "Mail Error: uid=1, saving=true");
	test_end();

	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
}

static void test_mail_set_critical_different_mailboxes(void)
{
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
	};

	struct test_mail_storage_ctx *ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box1 =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	test_assert(mailbox_open(box1) == 0);

	test_mail_save(box1,
		       "From: <test1@example.com>\n"
		       "\n"
		       "test body\n");

	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box1, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);

	const char *last_internal_error;
	enum mail_error mail_error;

	test_begin("mail_set_critical (different mailboxes)");
	test_expect_error_string("Mailbox INBOX: UID 1: Mail Error: uid 1");
	mail_set_critical(mail, "Mail Error: uid %u", mail->uid);
	test_expect_no_more_errors();
	last_internal_error = mail_get_last_internal_error(mail, &mail_error);
	test_assert_strcmp(last_internal_error, "Mail Error: uid 1");
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);

	struct mailbox *box2 =
		mailbox_alloc(ctx->user->namespaces->list, "testbox", 0);
	test_assert(mailbox_create(box2, NULL, FALSE) == 0);
	test_assert(mailbox_open(box2) == 0);
	struct mailbox_transaction_context *trans2 =
		mailbox_transaction_begin(box2, 0, __func__);
	mail = mail_alloc(trans2, 0, NULL);
	last_internal_error = mail_get_last_internal_error(mail, &mail_error);
	test_assert_strcmp(last_internal_error,
			   "Mailbox INBOX: UID 1: Mail Error: uid 1");
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans2) == 0);
	test_end();

	mailbox_free(&box2);
	mailbox_free(&box1);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
}

static void test_mail_get_last_internal_error(void)
{
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
	};

	struct test_mail_storage_ctx *ctx = test_mail_storage_init();
	test_mail_storage_init_user(ctx, &set);

	struct mailbox *box1 =
		mailbox_alloc(ctx->user->namespaces->list, "INBOX", 0);
	struct mailbox *box2 =
		mailbox_alloc(ctx->user->namespaces->list, "testbox", 0);
	test_assert(mailbox_create(box2, NULL, FALSE) == 0);
	test_assert(mailbox_open(box1) == 0);
	test_assert(mailbox_open(box2) == 0);

	for (int i = 0; i < 2; i++)
		test_mail_save(box1,
			       "From: <test1@example.com>\n"
			       "\n"
			       "test body\n");

	struct mailbox_transaction_context *trans1 =
		mailbox_transaction_begin(box1, 0, __func__);
	struct mailbox_transaction_context *trans2 =
		mailbox_transaction_begin(box2, 0, __func__);
	struct mail *mail1 = mail_alloc(trans1, 0, NULL);
	mail_set_seq(mail1, 1);
	struct mail *mail2 = mail_alloc(trans2, 0, NULL);
	struct mail_storage *storage = mailbox_get_storage(mail1->box);

	const char *last_internal_error;
	enum mail_error mail_error;

	test_begin("mail*_get_last_internal_error (mail_set_critical)");
	test_expect_error_string("Mailbox INBOX: UID 1: mail_set_critical");
	mail_set_critical(mail1, "mail_set_critical");
	test_expect_no_more_errors();

	last_internal_error = mail_get_last_internal_error(mail1, &mail_error);
	test_assert_strcmp(last_internal_error, "mail_set_critical");
	last_internal_error = mailbox_get_last_internal_error(box1, &mail_error);
	test_assert_strcmp(last_internal_error, "UID 1: mail_set_critical");
	last_internal_error = mail_get_last_internal_error(mail2, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: UID 1: mail_set_critical");
	last_internal_error = mailbox_get_last_internal_error(box2, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: UID 1: mail_set_critical");
	last_internal_error = mail_storage_get_last_internal_error(storage, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: UID 1: mail_set_critical");
	test_end();

	test_begin("mail*_get_last_internal_error (mailbox_set_critical)");
	test_expect_error_string("Mailbox INBOX: mailbox_set_critical");
	mailbox_set_critical(box1, "mailbox_set_critical");
	test_expect_no_more_errors();

	last_internal_error = mail_get_last_internal_error(mail1, &mail_error);
	test_assert_strcmp(last_internal_error, "mailbox_set_critical");
	last_internal_error = mailbox_get_last_internal_error(box1, &mail_error);
	test_assert_strcmp(last_internal_error, "mailbox_set_critical");
	last_internal_error = mail_get_last_internal_error(mail2, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: mailbox_set_critical");
	last_internal_error = mailbox_get_last_internal_error(box2, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: mailbox_set_critical");
	last_internal_error = mail_storage_get_last_internal_error(storage, &mail_error);
	test_assert_strcmp(last_internal_error, "Mailbox INBOX: mailbox_set_critical");
	test_end();

	test_begin("mail*_get_last_internal_error (mail_storage_set_critical)");
	test_expect_error_string("mail_storage_set_critical");
	mail_storage_set_critical(storage, "mail_storage_set_critical");
	test_expect_no_more_errors();

	last_internal_error = mail_get_last_internal_error(mail1, &mail_error);
	test_assert_strcmp(last_internal_error, "mail_storage_set_critical");
	last_internal_error = mailbox_get_last_internal_error(box1, &mail_error);
	test_assert_strcmp(last_internal_error, "mail_storage_set_critical");
	last_internal_error = mail_storage_get_last_internal_error(storage, &mail_error);
	test_assert_strcmp(last_internal_error, "mail_storage_set_critical");
	test_end();

	test_begin("mail*_get_last_internal_error (different UID)");
	struct mail *mail1b = mail_alloc(trans1, 0, NULL);
	mail_set_seq(mail1b, 2);
	test_expect_error_string("Mailbox INBOX: UID 1: mail_set_critical "
				 "(different UID)");
	mail_set_critical(mail1, "mail_set_critical (different UID)");
	test_expect_no_more_errors();
	last_internal_error = mail_get_last_internal_error(mail1, &mail_error);
	test_assert_strcmp(last_internal_error,
			   "mail_set_critical (different UID)");
	last_internal_error = mail_get_last_internal_error(mail1b, &mail_error);
	test_assert_strcmp(last_internal_error,
			   "UID 1: mail_set_critical (different UID)");
	test_end();

	mail_free(&mail1b);
	mail_free(&mail2);
	mail_free(&mail1);
	test_assert(mailbox_transaction_commit(&trans2) == 0);
	test_assert(mailbox_transaction_commit(&trans1) == 0);
	mailbox_free(&box2);
	mailbox_free(&box1);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
}

int main(int argc, char **argv)
{
	void (*const tests[])(void) = {
		test_mail_random_access,
		test_attachment_flags_during_header_fetch,
		test_bodystructure_reparsing,
		test_bodystructure_corruption_reparsing,
		test_binary_size_corruption_recompute,
		test_mbox_raw_istream_eof,
		test_mbox_raw_istream_expected_size_at_eof,
		test_mbox_raw_istream_from_after_empty_from,
		test_mbox_raw_istream_crlf_from_at_buffer_end,
		test_mbox_raw_istream_invalid_expected_size,
		test_mbox_raw_istream_expected_size_inside_crlf,
		test_mbox_out_of_uids,
		test_mbox_x_uid_overflow,
		test_mbox_update_min_next_uid_unsynced,
		test_mbox_raw_istream_reader_holds_data,
		test_mbox_raw_istream_body_size_long_from,
		test_mbox_raw_istream_nul_after_from,
		test_mbox_save_from_header_lines,
		test_mail_set_critical,
		test_mail_set_critical_different_mailboxes,
		test_mail_get_last_internal_error,
		NULL
	};
	int ret;

	master_service = master_service_init("test-mail",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");

	if (null_strcmp(argv[1], "-D") == 0)
		event_set_forced_debug(test_event, TRUE);
	test_dir_init("test-mail");
	ret = test_run(tests);
	master_service_deinit(&master_service);
	return ret;
}
