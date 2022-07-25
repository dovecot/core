/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fuzzer.h"

#include "message-part.h"
#include "message-part-data.h"
#include "imap-bodystructure.h"

#include <ctype.h>

static const char *str_sanitize_binary(const char *input)
{
	string_t *dest = t_str_new(strlen(input));
	for (;*input != '\0';input++) {
		if (!i_isprint(*input))
			str_printfa(dest, "<%02x>", (unsigned char)*input);
		else
			str_append_c(dest, *input);
	}
	return str_c(dest);
}

/* See imap_append_nstring_nolf() and remove_newlines_and_append(),
   we need to do this to compensate for the changes made emitting the
   re-encoded output to parse on the 2nd pass. */
static const char* suppress_crlfs(const char *src)
{
	if (src == NULL)
		return NULL;

	const char *ptr = strpbrk(src, "\r\n");
	if (ptr == NULL)
		return src;

	string_t *dst = t_str_new(strlen(src));
	str_append_data(dst, src, ptr - src);
	for (; *ptr != '\0'; ptr++) {
		switch(ptr[0]) {
		/* handle CRs and LFs ... */
		case '\r':
		case '\n':
			switch(ptr[1]) {
			/* ... CRs and LFs followed by a whitespace
			   OR at the end of the string are discarded */
			case ' ':
			case '\t':
			case '\r':
			case '\n':
			case '\0':
				break;
			default:
			/* .. CRs and LFs followed by a non-whitespace
			   are replaced themselves with a space */
				str_append_c(dst, ' ');
			}
			break;
		/* other characters are just copied */
		default:
			str_append_c(dst, ptr[0]);
		}
	}
	return str_c(dst);
}

static int compare_field(const char *s1, const char *s2)
{
	s1 = suppress_crlfs(s1);
	s2 = suppress_crlfs(s2);
	return null_strcmp(s1, s2);
}

static int compare_ignorecase(const char *s1, const char *s2)
{
	s1 = suppress_crlfs(s1);
	s2 = suppress_crlfs(s2);
	return null_strcasecmp(s1, s2);
}

/* Check additional strings beside parts scanned by message_part_is_equal(),
   to give the fuzzer a chance to explore the outcomes of the parenthesized
   lists string parser. */
static bool message_part_check_strings(const struct message_part *p1,
				       const struct message_part *p2)
{
	struct message_part_data *d1 = p1->data;
	struct message_part_data *d2 = p2->data;

	/* case sensitivity is determined for each field by the following RFCs:
	   RFC-1864: content_md5
	   RFC-2183: content_disposition
	   RFC-2045: content_type, content_subtype, content_transfer_encoding,
		     content_id, content_description
	   RFC-2110: content_location */

	/* In some cases (parts truncation et al) the content-type can be
	   replaced with application/octet-stream. If the reparsed type is
	   octect/stream, ignore the mismatch. */

	if ((compare_ignorecase(d1->content_type, d2->content_type) != 0 ||
	     compare_ignorecase(d1->content_subtype, d2->content_subtype) != 0) &&
	    (compare_ignorecase(d2->content_type, "application") != 0 ||
	     compare_ignorecase(d2->content_subtype, "octet-stream") != 0))
		return FALSE;

	if (compare_ignorecase(d1->content_transfer_encoding, d2->content_transfer_encoding) != 0 ||
	    compare_field     (d1->content_id, d2->content_id) != 0 ||
	    compare_field     (d1->content_description, d2->content_description) != 0 ||
	    compare_ignorecase(d1->content_disposition, d2->content_disposition) != 0 ||
	    compare_field     (d1->content_md5, d2->content_md5) != 0 ||
	    compare_field     (d1->content_location, d2->content_location) != 0)
		return FALSE;

	return TRUE;
}

FUZZ_BEGIN_STR(const char *bodystruct_orig)
{
	pool_t pool =
		pool_alloconly_create(MEMPOOL_GROWING"fuzz bodystructure", 1024);
	string_t *buffer = str_new(pool, 32);
	struct message_part *parts_orig  = NULL;
	struct message_part *parts_regen = NULL;
	const char *bodystruct_regen;
	const char *error ATTR_UNUSED;

	/* Non parsable is fine, this will be the most likely outcome as we
	   receive random sequences of bytes and not what we expect to parse. */
	if (imap_bodystructure_parse_full(
		bodystruct_orig, pool, &parts_orig, &error) == 0) {
		if (imap_bodystructure_write(
			parts_orig, buffer, TRUE, &error) != 0)
			i_panic("Failed to write bodystructure: %s", error);
		bodystruct_regen = t_strdup(str_c(buffer));

		/* The regenerated bodystructure must be parseable again.
		   In theory, it should produce the same result as the
		   first pass. In practice, however, some fields are altered
		   by imap_append_string_for_humans(). Therefore, the output
		   string MAY be slightly different but it must at least
		   retain the same parts topology and basic metadata as
		   checked by message_part_is_equal() (see Subject and
		   Addresses fields). */
		if (imap_bodystructure_parse_full(
			bodystruct_regen, pool, &parts_regen, &error) != 0)
			i_panic("Failed to reparse bodystructure\n'%s'\n'%s'",
				str_sanitize_binary(bodystruct_orig),
				str_sanitize_binary(bodystruct_regen));

		if (!message_part_is_equal_ex(
			parts_orig, parts_regen, message_part_check_strings))
			i_panic("Reparsed part fails message_part_is_equal()\n'%s'\n'%s'",
				str_sanitize_binary(bodystruct_orig),
				str_sanitize_binary(bodystruct_regen));
	}
	pool_unref(&pool);
}
FUZZ_END
