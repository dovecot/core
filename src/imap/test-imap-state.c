/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "numpack.h"
#include "seq-range-array.h"
#include "test-common.h"
#include "mail-storage-service.h"
#include "imap-common.h"
#include "imap-client.h"
#include "imap-feature.h"
#include "imap-state-private.h"

imap_client_created_func_t *hook_client_created = NULL;
bool imap_debug = FALSE;
bool verbose_proctitle = FALSE;

void imap_refresh_proctitle(void) { }
void imap_refresh_proctitle_delayed(void) { }
int client_create_from_input(const struct mail_storage_service_input *input ATTR_UNUSED,
			     const struct imap_logout_stats *stats ATTR_UNUSED,
			     int fd_in ATTR_UNUSED, int fd_out ATTR_UNUSED,
			     enum client_create_flags flags ATTR_UNUSED,
			     struct client **client_r ATTR_UNUSED,
			     const char **error_r ATTR_UNUSED) { return -1; }

static void test_import_string(void)
{
	test_begin("imap_state_import_string()");

	/* Valid NUL-terminated string. */
	const unsigned char buf1[] = "hello\0extra";
	const unsigned char *p = buf1;
	const char *s = NULL;
	test_assert(imap_state_import_string(&p, buf1 + sizeof(buf1) - 1, &s) == 0);
	test_assert(s != NULL && strcmp(s, "hello") == 0);
	test_assert(p == buf1 + 6);

	/* Empty string (just a NUL). */
	const unsigned char buf2[] = "\0rest";
	p = buf2;
	s = NULL;
	test_assert(imap_state_import_string(&p, buf2 + sizeof(buf2) - 1, &s) == 0);
	test_assert(s != NULL && s[0] == '\0');
	test_assert(p == buf2 + 1);

	/* No NUL before end -> -1. */
	const unsigned char buf3[] = { 'a', 'b', 'c' };
	p = buf3;
	s = NULL;
	test_assert(imap_state_import_string(&p, buf3 + sizeof(buf3), &s) == -1);

	/* Empty input -> -1. */
	p = buf3;
	test_assert(imap_state_import_string(&p, buf3, &s) == -1);

	test_end();
}

static void test_import_seq_range_roundtrip(void)
{
	test_begin("imap_state_import_seq_range() round-trip");

	ARRAY_TYPE(seq_range) src;
	t_array_init(&src, 8);
	seq_range_array_add(&src, 1);
	seq_range_array_add_range(&src, 5, 9);
	seq_range_array_add(&src, 100);
	seq_range_array_add_range(&src, 1000, 1005);

	buffer_t *enc = t_buffer_create(64);
	imap_state_export_seq_range(enc, &src);

	ARRAY_TYPE(seq_range) dst;
	t_array_init(&dst, 8);
	const unsigned char *p = enc->data;
	test_assert(imap_state_import_seq_range(&p, CONST_PTR_OFFSET(enc->data, enc->used),
				     &dst) == 0);
	test_assert(p == CONST_PTR_OFFSET(enc->data, enc->used));

	const struct seq_range *a, *b;
	unsigned int an, bn;
	a = array_get(&src, &an);
	b = array_get(&dst, &bn);
	test_assert(an == bn);
	for (unsigned int i = 0; i < an && i < bn; i++) {
		test_assert_idx(a[i].seq1 == b[i].seq1, i);
		test_assert_idx(a[i].seq2 == b[i].seq2, i);
	}

	test_end();
}

static void test_import_seq_range_truncated(void)
{
	test_begin("imap_state_import_seq_range() truncated");

	ARRAY_TYPE(seq_range) src;
	t_array_init(&src, 4);
	seq_range_array_add_range(&src, 1, 10);
	seq_range_array_add_range(&src, 50, 60);

	buffer_t *enc = t_buffer_create(64);
	imap_state_export_seq_range(enc, &src);

	/* Cut off any number of trailing bytes - decode must reject. */
	for (size_t cut = 1; cut < enc->used; cut++) {
		ARRAY_TYPE(seq_range) dst;
		t_array_init(&dst, 4);
		const unsigned char *p = enc->data;
		test_assert_idx(imap_state_import_seq_range(&p,
				CONST_PTR_OFFSET(enc->data, enc->used - cut),
				&dst) == -1, cut);
	}

	test_end();
}

static void test_import_seq_range_overflow(void)
{
	test_begin("imap_state_import_seq_range() overflow rejected");

	/* Single range whose first encoded num would push uid1 past
	   UINT32_MAX. With next_uid = 1 and (num >> 1) = UINT32_MAX, we
	   need num = UINT32_MAX & ~1 = 0xfffffffe (bit 0 = single uid).
	   Then uid1 = 1 + 0x7fffffff = 0x80000000. Use an even larger
	   value to actually overflow. */
	buffer_t *enc = t_buffer_create(32);
	numpack_encode(enc, 1);          /* count = 1 */
	/* (num >> 1) = UINT32_MAX, low bit 0 -> single-uid form; uid1
	   would be 1 + UINT32_MAX = overflow. */
	numpack_encode(enc, ((uint64_t)UINT32_MAX) << 1);

	ARRAY_TYPE(seq_range) dst;
	t_array_init(&dst, 4);
	const unsigned char *p = enc->data;
	test_assert(imap_state_import_seq_range(&p,
		CONST_PTR_OFFSET(enc->data, enc->used), &dst) == -1);

	/* Range form: uid1 = 1, then num = UINT32_MAX -> uid2 = uid1 +
	   num + 1 overflows. */
	buffer_set_used_size(enc, 0);
	numpack_encode(enc, 1);          /* count = 1 */
	numpack_encode(enc, 1);          /* (0 << 1) | 1 -> range, uid1 = 1 */
	numpack_encode(enc, UINT32_MAX); /* range length */

	t_array_init(&dst, 4);
	p = enc->data;
	test_assert(imap_state_import_seq_range(&p,
		CONST_PTR_OFFSET(enc->data, enc->used), &dst) == -1);

	/* next_uid wrap: a single-uid range at UINT32_MAX followed by
	   another range. First range valid; second computation would wrap
	   next_uid. */
	buffer_set_used_size(enc, 0);
	numpack_encode(enc, 2);                /* count = 2 */
	/* uid1 = 1 + (UINT32_MAX-1)/2*2... use single-uid form with
	   (num >> 1) = UINT32_MAX - 1 so uid1 = UINT32_MAX. */
	numpack_encode(enc, ((uint64_t)(UINT32_MAX - 1)) << 1);
	numpack_encode(enc, 0);                /* second entry */

	t_array_init(&dst, 4);
	p = enc->data;
	test_assert(imap_state_import_seq_range(&p,
		CONST_PTR_OFFSET(enc->data, enc->used), &dst) == -1);

	/* Two iterations: first range is valid but pushes next_uid above
	   0x80000000, then the single-uid gap check on the second entry must
	   reject even though num itself is a valid uint32.
	   1st: single uid, (num>>1) = 0x7fffffff -> uid1 = 0x80000000,
	   next_uid = 0x80000001.
	   2nd: single uid, (num>>1) = 0x7fffffff; 0x80000001 + 0x7fffffff
	   would overflow, so (num>>1) > UINT32_MAX - next_uid triggers. */
	buffer_set_used_size(enc, 0);
	numpack_encode(enc, 2);                          /* count = 2 */
	numpack_encode(enc, ((uint64_t)0x7fffffffU) << 1); /* uid1 = 0x80000000 */
	numpack_encode(enc, ((uint64_t)0x7fffffffU) << 1); /* overflows */

	t_array_init(&dst, 4);
	p = enc->data;
	test_assert(imap_state_import_seq_range(&p,
		CONST_PTR_OFFSET(enc->data, enc->used), &dst) == -1);

	/* Range-form overflow at a higher uid1: uid1 = 0x40000001, then a
	   range length num = UINT32_MAX would overflow uid2. */
	buffer_set_used_size(enc, 0);
	numpack_encode(enc, 1);                          /* count = 1 */
	numpack_encode(enc, (((uint64_t)0x40000000U) << 1) | 1); /* range, uid1 = 0x40000001 */
	numpack_encode(enc, UINT32_MAX);                 /* range length */

	t_array_init(&dst, 4);
	p = enc->data;
	test_assert(imap_state_import_seq_range(&p,
		CONST_PTR_OFFSET(enc->data, enc->used), &dst) == -1);

	test_end();
}

static void test_import_state_searchres_duplicate(void)
{
	struct client client;
	size_t skip;
	const char *error;
	/* Empty seq-range payload: numpack count = 0. */
	const unsigned char payload[] = { 0x00 };

	test_begin("imap_state_import_searchres() duplicate rejected");

	i_zero(&client);
	error = NULL;
	test_assert(imap_state_import_searchres(&client, payload, sizeof(payload),
					   &skip, &error) == IMAP_STATE_OK);
	test_assert(array_is_created(&client.search_saved_uidset));

	error = NULL;
	test_assert(imap_state_import_searchres(&client, payload, sizeof(payload),
					   &skip, &error) == IMAP_STATE_CORRUPTED);
	test_assert(error != NULL);

	array_free(&client.search_saved_uidset);
	test_end();
}

static void test_import_state_compress_unknown(void)
{
	struct client client;
	size_t skip;
	const char *error;
	const unsigned char name[] = "no-such-handler";

	test_begin("imap_state_import_compress() unknown handler rejected");

	i_zero(&client);
	error = NULL;
	test_assert(imap_state_import_compress(&client, name, sizeof(name),
					  &skip, &error) == IMAP_STATE_CORRUPTED);
	test_assert(error != NULL);

	/* Truncated (no NUL terminator) must also be rejected. */
	const unsigned char trunc[] = { 'z', 'l', 'i', 'b' };
	error = NULL;
	test_assert(imap_state_import_compress(&client, trunc, sizeof(trunc),
					  &skip, &error) == IMAP_STATE_CORRUPTED);
	test_assert(error != NULL);

	test_end();
}

static void test_import_state_enabled_feature_unknown(void)
{
	struct client client;
	size_t skip;
	const char *error;
	const unsigned char name[] = "NO-SUCH-FEATURE";

	test_begin("imap_state_import_enabled_feature() unknown feature rejected");

	imap_features_init();
	i_zero(&client);
	error = NULL;
	test_assert(imap_state_import_enabled_feature(&client, name, sizeof(name),
						 &skip, &error) == IMAP_STATE_CORRUPTED);
	test_assert(error != NULL);

	/* Truncated name must also be rejected. */
	const unsigned char trunc[] = { 'C', 'O', 'N', 'D' };
	error = NULL;
	test_assert(imap_state_import_enabled_feature(&client, trunc, sizeof(trunc),
						 &skip, &error) == IMAP_STATE_CORRUPTED);
	test_assert(error != NULL);

	imap_features_deinit();
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_import_string,
		test_import_seq_range_roundtrip,
		test_import_seq_range_truncated,
		test_import_seq_range_overflow,
		test_import_state_searchres_duplicate,
		test_import_state_compress_unknown,
		test_import_state_enabled_feature_unknown,
		NULL
	};

	return test_run(test_functions);
}
