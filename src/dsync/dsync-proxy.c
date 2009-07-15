/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "hex-binary.h"
#include "mail-types.h"
#include "imap-util.h"
#include "dsync-data.h"
#include "dsync-proxy.h"

#include <stdlib.h>

void dsync_proxy_msg_export(string_t *str,
			    const struct dsync_message *msg)
{
	str_tabescape_write(str, msg->guid);
	str_printfa(str, "\t%u\t%llu\t", msg->uid,
		    (unsigned long long)msg->modseq);
	if ((msg->flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0)
		str_append(str, "\\dsync-expunged ");
	imap_write_flags(str, msg->flags & MAIL_FLAGS_NONRECENT, msg->keywords);
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

	msg_r->flags &= ~MAIL_RECENT;
	msg_r->keywords = array_idx(&keywords, 0);
	return 0;
}

int dsync_proxy_msg_import_unescaped(pool_t pool, struct dsync_message *msg_r,
				     const char *const *args,
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
		ret = dsync_proxy_msg_import_unescaped(pool, msg_r,
					(const char *const *)args, error_r);
	} T_END;
	return ret;
}

void dsync_proxy_mailbox_export(string_t *str,
				const struct dsync_mailbox *box)
{
	str_tabescape_write(str, box->name);
	if (box->uid_validity == 0) {
		/* \noselect mailbox */
		return;
	}

	str_printfa(str, "\t%s\t%u\t%u\t%llu",
		    binary_to_hex(box->guid.guid, sizeof(box->guid.guid)),
		    box->uid_validity, box->uid_next,
		    (unsigned long long)box->highest_modseq);
}

static int
mailbox_parse_args(pool_t pool, struct dsync_mailbox *box,
		   const char *const *args, const char **error_r)
{
	string_t *str;
	unsigned int count;
	char *p;

	count = str_array_length(args);
	if (count != 1 && count != 5) {
		*error_r = "Mailbox missing parameters";
		return -1;
	}

	/* name guid uid_validity uid_next highest_modseq */
	str = t_str_new(128);
	str_append_tabunescaped(str, args[0], strlen(args[0]));
	box->name = p_strdup(pool, str_c(str));

	if (args[1] == NULL) {
		/* \noselect mailbox */
		return 0;
	}

	str_truncate(str, 0);
	if (hex_to_binary(args[1], str) < 0) {
		*error_r = "Invalid hex in mailbox GUID";
		return -1;
	} else if (str_len(str) != sizeof(box->guid)) {
		*error_r = "Invalid mailbox GUID size";
		return -1;
	} else {
		memcpy(box->guid.guid, str_data(str), sizeof(box->guid.guid));
	}

	box->uid_validity = strtoul(args[2], &p, 10);
	if (box->uid_validity == 0 || *p != '\0') {
		*error_r = "Invalid mailbox uid_validity";
		return -1;
	}

	box->uid_next = strtoul(args[3], &p, 10);
	if (box->uid_validity == 0 || *p != '\0') {
		*error_r = "Invalid mailbox uid_next";
		return -1;
	}

	box->highest_modseq = strtoull(args[4], &p, 10);
	if (*p != '\0') {
		*error_r = "Invalid mailbox highest_modseq";
		return -1;
	}
	return 0;
}

int dsync_proxy_mailbox_import(pool_t pool, const char *str,
			       struct dsync_mailbox *box_r,
			       const char **error_r)
{
	int ret;

	memset(box_r, 0, sizeof(*box_r));
	T_BEGIN {
		ret = mailbox_parse_args(pool, box_r,
					 t_strsplit(str, "\t"), error_r);
	} T_END;
	return ret;
}

void dsync_proxy_mailbox_guid_export(string_t *str,
				     const mailbox_guid_t *mailbox)
{
	str_append(str, binary_to_hex(mailbox->guid, sizeof(mailbox->guid)));
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
