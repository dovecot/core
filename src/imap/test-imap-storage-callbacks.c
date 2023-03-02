/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-subprocess.h"
#include "imap-storage-callbacks.h"

#include <stdio.h>

void client_send_line(struct client *client ATTR_UNUSED, const char *data ATTR_UNUSED)
{
}

#define non_0  	  1
#define t_non_0	  { .tv_sec = non_0 }
#define t_zero 	  { .tv_sec = 0 }
#define t_10sec	  { .tv_sec = 10 }
#define t_42sec	  { .tv_sec = 42 }

static const struct test_vector {
	const struct mail_storage_progress_details dtl;
	const char *tag;
	const char *expect;
} test_vectors[] = {
{ .dtl = { .processed = 0,     .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS] Hang in there.." },
{ .dtl = { .processed = 0,     .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = "tag]", .expect = "* OK [INPROGRESS] Hang in there.." },
{ .dtl = { .processed = 0,     .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = "tag",  .expect = "* OK [INPROGRESS (\"tag\" NIL NIL)] Hang in there.." },
{ .dtl = { .processed = non_0, .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = "tag",  .expect = "* OK [INPROGRESS (\"tag\" 1 NIL)] Processed 1 item(s)" },
{ .dtl = { .processed = non_0, .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = "tag]", .expect = "* OK [INPROGRESS (NIL 1 NIL)] Processed 1 item(s)" },
{ .dtl = { .processed = non_0, .total = 0,     .now = t_non_0,	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 1 NIL)] Processed 1 item(s)" },
{ .dtl = { .processed = 0,     .total = non_0, .now = t_zero,   .verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 0 1)] Processed 0% of the mailbox" },
{ .dtl = { .processed = 0,     .total = non_0, .now = t_non_0, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 0 1)] Processed 0% of the mailbox" },
{ .dtl = { .processed = 0,     .total = non_0, .now = t_zero,   .verb = "",   }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 0 1)] Processed 0% of the mailbox" },
{ .dtl = { .processed = 0,     .total = non_0, .now = t_zero,   .verb = "At", }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 0 1)] At 0% of the mailbox" },
{ .dtl = { .processed = 42,    .total = 100,   .now = t_zero,   .verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 42 100)] Processed 42% of the mailbox" },
{ .dtl = { .processed = 42,    .total = 100,   .now = t_42sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 42 100)] Processed 42% of the mailbox, ETA 0:58" },
{ .dtl = { .processed = 20,    .total = 60,    .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 20 60)] Processed 33% of the mailbox, ETA 0:20" },
{ .dtl = { .processed = 229,   .total = 1000,  .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 229 1000)] Processed 22% of the mailbox, ETA 0:33" },
{ .dtl = { .processed = 2000,  .total = 1000,  .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 999 1000)] Processed 99% of the mailbox, ETA 0:00" },
{ .dtl = { .processed = 3,     .total = 2,     .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 1 2)] Processed 50% of the mailbox, ETA 0:10" },
{ .dtl = { .processed = 2,     .total = 2,     .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 1 2)] Processed 50% of the mailbox, ETA 0:10" },
{ .dtl = { .processed = 1,     .total = 2,     .now = t_10sec, 	.verb = NULL, }, .tag = NULL,   .expect = "* OK [INPROGRESS (NIL 1 2)] Processed 50% of the mailbox, ETA 0:10" },
};

static void test_imap_storage_callback_line(void)
{
	test_begin("imap_storage_callback_line");
	for (unsigned int index = 0; index < N_ELEMENTS(test_vectors); ++index ) {
		const struct test_vector *v = test_vectors + index;
		const char *actual = imap_storage_callback_line(&v->dtl, v->tag);
		test_assert_strcmp_idx(v->expect, actual, index);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_storage_callback_line,
		NULL
	};

	return test_run(test_functions);
}
