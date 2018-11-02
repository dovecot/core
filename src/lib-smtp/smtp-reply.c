/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strfuncs.h"
#include "smtp-reply.h"

void smtp_reply_init(struct smtp_reply *reply, unsigned int status,
	const char *text)
{
	const char **text_lines = t_new(const char *, 2);

	text_lines[0] = text;
	text_lines[1] = NULL;

	i_zero(reply);
	reply->status = status;
	reply->text_lines = text_lines;
}

void smtp_reply_printf(struct smtp_reply *reply, unsigned int status,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	smtp_reply_init(reply, status, t_strdup_vprintf(format, args));
	va_end(args);
}

const char *
smtp_reply_get_enh_code(const struct smtp_reply *reply)
{
	if (reply->enhanced_code.x < 2)
		return NULL;
	if (reply->enhanced_code.x >= 6)
		return NULL;

	return t_strdup_printf("%u.%u.%u",
		reply->enhanced_code.x, reply->enhanced_code.y, reply->enhanced_code.z);
}

const char *const *
smtp_reply_get_text_lines_omit_prefix(const struct smtp_reply *reply)
{
	unsigned int lines_count, i;
	const char **lines;
	const char *p;

	if ((p=strchr(reply->text_lines[0], ' ')) == NULL)
		return reply->text_lines;

	lines_count = str_array_length(reply->text_lines);
	lines = t_new(const char *, lines_count + 1);

	lines[0] = p + 1;
	for (i = 1; i < lines_count; i++)
		lines[i] = reply->text_lines[i];

	return lines;
}

void
smtp_reply_write(string_t *out, const struct smtp_reply *reply)
{
	const char *prefix, *enh_code;
	const char *const *lines;

	i_assert(reply->status < 560);
	i_assert(reply->enhanced_code.x < 6);

	prefix = t_strdup_printf("%03u", reply->status);
	enh_code = smtp_reply_get_enh_code(reply);

	if (reply->text_lines == NULL || *reply->text_lines == NULL) {
		str_append(out, prefix);
		if (enh_code != NULL) {
			str_append_c(out, ' ');
			str_append(out, enh_code);
		}
		str_append(out, " \r\n");
		return;
	}

	lines = reply->text_lines;
	while (*lines != NULL) {
		str_append(out, prefix);
		if (*(lines+1) == NULL)
			str_append_c(out, ' ');
		else
			str_append_c(out, '-');
		if (enh_code != NULL) {
			str_append(out, enh_code);
			str_append_c(out, ' ');
		}
		str_append(out, *lines);
		str_append(out, "\r\n");
		lines++;
	}
}

void smtp_reply_write_one_line(string_t *out, const struct smtp_reply *reply)
{
	const char *enh_code = smtp_reply_get_enh_code(reply);
	const char *const *lines;

	i_assert(reply->status < 560);
	i_assert(reply->enhanced_code.x < 6);

	str_printfa(out, "%03u", reply->status);
	if (enh_code != NULL) {
		str_append_c(out, ' ');
		str_append(out, enh_code);
	}

	lines = reply->text_lines;
	while (*lines != NULL) {
		str_append_c(out, ' ');
		str_append(out, *lines);
		lines++;
	}
}

const char *smtp_reply_log(const struct smtp_reply *reply)
{
	const char *const *lines;
	string_t *msg = t_str_new(256);

	if (smtp_reply_is_remote(reply)) {
		const char *enh_code = smtp_reply_get_enh_code(reply);

		str_printfa(msg, "%03u", reply->status);
		if (enh_code != NULL) {
			str_append_c(msg, ' ');
			str_append(msg, enh_code);
		}
	}

	lines = reply->text_lines;
	while (*lines != NULL) {
		if (str_len(msg) > 0)
			str_append_c(msg, ' ');
		str_append(msg, *lines);
		lines++;
	}
	return str_c(msg);
}

void smtp_reply_copy(pool_t pool, struct smtp_reply *dst,
	const struct smtp_reply *src)
{
	*dst = *src;
	dst->text_lines = p_strarray_dup(pool, src->text_lines);
}

struct smtp_reply *smtp_reply_clone(pool_t pool,
	const struct smtp_reply *src)
{
	struct smtp_reply *dst;

	dst = p_new(pool, struct smtp_reply, 1);
	smtp_reply_copy(pool, dst, src);

	return dst;
}
