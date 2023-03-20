/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "istream.h"
#include "master-service.h"
#include "message-size.h"
#include "test-mail-storage-common.h"

static struct event *test_event;

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
	unsigned int lines;
	bool binary;
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
						     &size, &binary, &input);
			if (ret == 0)
				i_stream_unref(&input);
		} else {
			ret = mail_get_binary_size(mail, parts,
						   i_rand_limit(2) == 0,
						   &size, &lines);
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
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = (const char *const[]) {
			"mail_attachment_detection_options=add-flags",
			t_strconcat("mail_never_cache_fields=",
				    never_cache_fields, NULL),
			NULL
		},
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
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = (const char *const[]) {
			"mail_attachment_detection_options=add-flags",
			"mail_never_cache_fields=mime.parts",
			NULL
		},
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
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = (const char *const[]) {
			"mail_attachment_detection_options=add-flags",
			"mail_never_cache_fields=flags",
			NULL
		},
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
		test_mail_set_critical,
		test_mail_set_critical_different_mailboxes,
		test_mail_get_last_internal_error,
		NULL
	};
	int ret;

	master_service = master_service_init("test-mail",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");

	test_event = event_create(NULL);
	if (null_strcmp(argv[1], "-D") == 0)
		event_set_forced_debug(test_event, TRUE);
	ret = test_run(tests);
	event_unref(&test_event);
	master_service_deinit(&master_service);
	return ret;
}
