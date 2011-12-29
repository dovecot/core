/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "hex-binary.h"
#include "mail-types.h"
#include "imap-util.h"
#include "mail-cache.h"
#include "dsync-data.h"
#include "dsync-proxy.h"

#include <stdlib.h>

#define DSYNC_CACHE_DECISION_NO 'n'
#define DSYNC_CACHE_DECISION_YES 'y'
#define DSYNC_CACHE_DECISION_TEMP 't'
#define DSYNC_CACHE_DECISION_FORCED 'f'

void dsync_proxy_cache_fields_export(string_t *str,
				     const ARRAY_TYPE(mailbox_cache_field) *_fields)
{
	const struct mailbox_cache_field *fields;
	unsigned int i, count;

	if (!array_is_created(_fields))
		return;

	fields = array_get(_fields, &count);
	for (i = 0; i < count; i++) {
		str_append_c(str, '\t');
		str_tabescape_write(str, fields[i].name);
		str_append_c(str, '\t');
		switch (fields[i].decision & ~MAIL_CACHE_DECISION_FORCED) {
		case MAIL_CACHE_DECISION_NO:
			str_append_c(str, DSYNC_CACHE_DECISION_NO);
			break;
		case MAIL_CACHE_DECISION_YES:
			str_append_c(str, DSYNC_CACHE_DECISION_YES);
			break;
		case MAIL_CACHE_DECISION_TEMP:
			str_append_c(str, DSYNC_CACHE_DECISION_TEMP);
			break;
		}
		if ((fields[i].decision & MAIL_CACHE_DECISION_FORCED) != 0)
			str_append_c(str, DSYNC_CACHE_DECISION_FORCED);
		str_printfa(str, "\t%ld", fields[i].last_used);
	}
}

static int dsync_proxy_cache_dec_parse(const char *str,
				       enum mail_cache_decision_type *dec_r)
{
	switch (*str++) {
	case DSYNC_CACHE_DECISION_NO:
		*dec_r = MAIL_CACHE_DECISION_NO;
		break;
	case DSYNC_CACHE_DECISION_YES:
		*dec_r = MAIL_CACHE_DECISION_YES;
		break;
	case DSYNC_CACHE_DECISION_TEMP:
		*dec_r = MAIL_CACHE_DECISION_TEMP;
		break;
	default:
		return -1;
	}
	if (*str == DSYNC_CACHE_DECISION_FORCED) {
		*dec_r |= MAIL_CACHE_DECISION_FORCED;
		str++;
	}
	if (*str != '\0')
		return -1;
	return 0;
}

int dsync_proxy_cache_fields_import(const char *const *args, pool_t pool,
				    ARRAY_TYPE(mailbox_cache_field) *fields,
				    const char **error_r)
{
	struct mailbox_cache_field *cache_field;
	enum mail_cache_decision_type dec;
	unsigned int i, count = str_array_length(args);

	if (count % 3 != 0) {
		*error_r = "Invalid mailbox cache fields";
		return -1;
	}
	if (!array_is_created(fields))
		p_array_init(fields, pool, (count/3) + 1);
	for (i = 0; i < count; i += 3) {
		cache_field = array_append_space(fields);
		cache_field->name = p_strdup(pool, args[i]);

		if (dsync_proxy_cache_dec_parse(args[i+1], &dec) < 0) {
			*error_r = "Invalid cache decision";
			return -1;
		}
		cache_field->decision = dec;
		if (str_to_time(args[i+2], &cache_field->last_used) < 0) {
			*error_r = "Invalid cache last_used";
			return -1;
		}
	}
	return 0;
}

void dsync_proxy_msg_export(string_t *str,
			    const struct dsync_message *msg)
{
	str_tabescape_write(str, msg->guid);
	str_printfa(str, "\t%u\t%llu\t", msg->uid,
		    (unsigned long long)msg->modseq);
	if ((msg->flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0)
		str_append(str, "\\dsync-expunged ");
	imap_write_flags(str, msg->flags & MAIL_FLAGS_MASK, msg->keywords);
	str_printfa(str, "\t%ld", (long)msg->save_date);
}

int dsync_proxy_msg_parse_flags(pool_t pool, const char *str,
				struct dsync_message *msg_r)
{
	ARRAY_TYPE(const_string) keywords;
	const char *const *args, *kw;
	enum mail_flags flag;

	msg_r->flags = 0;
	p_array_init(&keywords, pool, 16);
	for (args = t_strsplit_spaces(str, " "); *args != NULL; args++) {
		if (**args != '\\') {
			kw = p_strdup(pool, *args);
			array_append(&keywords, &kw, 1);
		} else if (strcasecmp(*args, "\\dsync-expunged") == 0) {
			msg_r->flags |= DSYNC_MAIL_FLAG_EXPUNGED;
		} else {
			flag = imap_parse_system_flag(*args);
			if (flag == 0)
				return -1;
			msg_r->flags |= flag;
		}
	}
	(void)array_append_space(&keywords);

	msg_r->keywords = array_idx(&keywords, 0);
	return 0;
}

int dsync_proxy_msg_import_unescaped(pool_t pool, const char *const *args,
				     struct dsync_message *msg_r,
				     const char **error_r)
{
	/* guid uid modseq flags save_date */
	if (str_array_length(args) < 5) {
		*error_r = "Missing parameters";
		return -1;
	}

	memset(msg_r, 0, sizeof(*msg_r));
	msg_r->guid = p_strdup(pool, args[0]);
	msg_r->uid = strtoul(args[1], NULL, 10);
	msg_r->modseq = strtoull(args[2], NULL, 10);
	if (dsync_proxy_msg_parse_flags(pool, args[3], msg_r) < 0) {
		*error_r = "Invalid system flags";
		return -1;
	}
	msg_r->save_date = strtoul(args[4], NULL, 10);
	return 0;
}

int dsync_proxy_msg_import(pool_t pool, const char *str,
			   struct dsync_message *msg_r, const char **error_r)
{
	char **args;
	unsigned int i;
	int ret;

	T_BEGIN {
		args = p_strsplit(pool_datastack_create(), str, "\t");
		for (i = 0; args[i] != NULL; i++)
			args[i] = str_tabunescape(args[i]);
		ret = dsync_proxy_msg_import_unescaped(pool,
						(const char *const *)args,
						msg_r, error_r);
	} T_END;
	return ret;
}

void dsync_proxy_msg_static_export(string_t *str,
				   const struct dsync_msg_static_data *msg)
{
	str_printfa(str, "%ld\t", (long)msg->received_date);
	str_tabescape_write(str, msg->pop3_uidl);
}

int dsync_proxy_msg_static_import_unescaped(pool_t pool,
					    const char *const *args,
					    struct dsync_msg_static_data *msg_r,
					    const char **error_r)
{
	/* received_date pop3_uidl */
	if (str_array_length(args) < 2) {
		*error_r = "Missing parameters";
		return -1;
	}

	memset(msg_r, 0, sizeof(*msg_r));
	msg_r->received_date = strtoul(args[0], NULL, 10);
	msg_r->pop3_uidl = p_strdup(pool, args[1]);
	return 0;
}

int dsync_proxy_msg_static_import(pool_t pool, const char *str,
				  struct dsync_msg_static_data *msg_r,
				  const char **error_r)
{
	char **args;
	unsigned int i;
	int ret;

	T_BEGIN {
		args = p_strsplit(pool_datastack_create(), str, "\t");
		for (i = 0; args[i] != NULL; i++)
			args[i] = str_tabunescape(args[i]);
		ret = dsync_proxy_msg_static_import_unescaped(pool, 
						(const char *const *)args,
						msg_r, error_r);
	} T_END;
	return ret;
}

void dsync_proxy_mailbox_export(string_t *str,
				const struct dsync_mailbox *box)
{
	char s[2];

	str_tabescape_write(str, box->name);
	str_append_c(str, '\t');
	s[0] = box->name_sep; s[1] = '\0';
	str_tabescape_write(str, s);
	str_printfa(str, "\t%lu\t%u", (unsigned long)box->last_change,
		    box->flags);

	if (dsync_mailbox_is_noselect(box)) {
		i_assert(box->uid_validity == 0);
		return;
	}
	i_assert(box->uid_validity != 0 ||
		 (box->flags & DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0);
	i_assert(box->uid_validity == 0 || box->uid_next != 0);

	str_append_c(str, '\t');
	dsync_proxy_mailbox_guid_export(str, &box->mailbox_guid);
	str_printfa(str, "\t%u\t%u\t%u\t%llu\t%u",
		    box->uid_validity, box->uid_next, box->message_count,
		    (unsigned long long)box->highest_modseq,
		    box->first_recent_uid);
	dsync_proxy_cache_fields_export(str, &box->cache_fields);
}

int dsync_proxy_mailbox_import_unescaped(pool_t pool, const char *const *args,
					 struct dsync_mailbox *box_r,
					 const char **error_r)
{
	unsigned int i = 0, count;
	bool box_deleted;
	char *p;

	memset(box_r, 0, sizeof(*box_r));

	count = str_array_length(args);
	if (count != 4 && count < 8) {
		*error_r = "Mailbox missing parameters";
		return -1;
	}

	/* name dir_guid mailbox_guid uid_validity uid_next
	   message_count highest_modseq */
	box_r->name = p_strdup(pool, args[i++]);
	dsync_str_sha_to_guid(box_r->name, &box_r->name_sha1);

	if (strlen(args[i]) > 1) {
		*error_r = "Invalid mailbox name hierarchy separator";
		return -1;
	}
	box_r->name_sep = args[i++][0];

	box_r->last_change = strtoul(args[i++], &p, 10);
	if (*p != '\0') {
		*error_r = "Invalid mailbox last_change";
		return -1;
	}
	box_r->flags = strtoul(args[i++], &p, 10);
	if (*p != '\0' ||
	    (dsync_mailbox_is_noselect(box_r) != (args[i] == NULL))) {
		*error_r = "Invalid mailbox flags";
		return -1;
	}
	box_deleted = (box_r->flags & (DSYNC_MAILBOX_FLAG_DELETED_MAILBOX |
				       DSYNC_MAILBOX_FLAG_DELETED_DIR)) != 0;
	if (box_r->name_sep == '\0' && !box_deleted) {
		*error_r = "Missing mailbox name hierarchy separator";
		return -1;
	}

	if (args[i] == NULL) {
		/* \noselect mailbox */
		return 0;
	}

	if (dsync_proxy_mailbox_guid_import(args[i++],
					    &box_r->mailbox_guid) < 0) {
		*error_r = "Invalid mailbox GUID";
		return -1;
	}

	box_r->uid_validity = strtoul(args[i++], &p, 10);
	if (*p != '\0' || (box_r->uid_validity == 0 && !box_deleted)) {
		abort();
		*error_r = "Invalid mailbox uid_validity";
		return -1;
	}

	box_r->uid_next = strtoul(args[i++], &p, 10);
	if (*p != '\0' || (box_r->uid_next == 0 && !box_deleted)) {
		*error_r = "Invalid mailbox uid_next";
		return -1;
	}

	box_r->message_count = strtoul(args[i++], &p, 10);
	if (*p != '\0') {
		*error_r = "Invalid mailbox message_count";
		return -1;
	}

	box_r->highest_modseq = strtoull(args[i++], &p, 10);
	if (*p != '\0') {
		*error_r = "Invalid mailbox highest_modseq";
		return -1;
	}

	box_r->first_recent_uid = strtoul(args[i++], &p, 10);
	if (*p != '\0') {
		*error_r = "Invalid mailbox first_recent_uid";
		return -1;
	}

	args += i;
	count -= i;
	if (dsync_proxy_cache_fields_import(args, pool, &box_r->cache_fields,
					    error_r) < 0)
		return -1;
	return 0;
}

int dsync_proxy_mailbox_import(pool_t pool, const char *str,
			       struct dsync_mailbox *box_r,
			       const char **error_r)
{
	char **args;
	int ret;

	T_BEGIN {
		args = p_strsplit(pool_datastack_create(), str, "\t");
		if (args[0] != NULL)
			args[0] = str_tabunescape(args[0]);
		ret = dsync_proxy_mailbox_import_unescaped(pool,
						(const char *const *)args,
						box_r, error_r);
	} T_END;
	return ret;
}

void dsync_proxy_mailbox_guid_export(string_t *str,
				     const mailbox_guid_t *mailbox)
{
	str_append(str, dsync_guid_to_str(mailbox));
}

int dsync_proxy_mailbox_guid_import(const char *str, mailbox_guid_t *guid_r)
{
	buffer_t *buf;

	buf = buffer_create_dynamic(pool_datastack_create(),
				    sizeof(guid_r->guid));
	if (hex_to_binary(str, buf) < 0 || buf->used != sizeof(guid_r->guid))
		return -1;
	memcpy(guid_r->guid, buf->data, sizeof(guid_r->guid));
	return 0;
}

void dsync_proxy_send_dot_output(struct ostream *output, bool *last_lf,
				 const unsigned char *data, size_t size)
{
	size_t i, start;

	i_assert(size > 0);

	if (*last_lf && data[0] == '.')
		o_stream_send(output, ".", 1);

	for (i = 1, start = 0; i < size; i++) {
		if (data[i-1] == '\n' && data[i] == '.') {
			o_stream_send(output, data + start, i - start);
			o_stream_send(output, ".", 1);
			start = i;
		}
	}
	o_stream_send(output, data + start, i - start);
	*last_lf = data[i-1] == '\n';
	i_assert(i == size);
}
