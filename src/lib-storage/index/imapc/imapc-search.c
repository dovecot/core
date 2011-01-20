/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "safe-mkstemp.h"
#include "write-full.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-date.h"
#include "mail-user.h"
#include "index-mail.h"
#include "imapc-client.h"
#include "imapc-storage.h"

struct mail_search_context *
imapc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program)
{
	return index_storage_search_init(t, args, sort_program);
}

bool imapc_search_next_nonblock(struct mail_search_context *_ctx,
				struct mail *mail, bool *tryagain_r)
{
	struct mail_private *pmail = (struct mail_private *)mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)mail->box;
	string_t *str;
	unsigned int orig_len;

	if (!index_storage_search_next_nonblock(_ctx, mail, tryagain_r))
		return FALSE;

	str = t_str_new(64);
	str_printfa(str, "UID FETCH %u (", mail->uid);
	orig_len = str_len(str);

	if ((pmail->wanted_fields & (MAIL_FETCH_MESSAGE_PARTS |
				     MAIL_FETCH_NUL_STATE |
				     MAIL_FETCH_IMAP_BODY |
				     MAIL_FETCH_IMAP_BODYSTRUCTURE |
				     MAIL_FETCH_PHYSICAL_SIZE |
				     MAIL_FETCH_VIRTUAL_SIZE)) != 0)
		str_append(str, "BODY.PEEK[] ");
	else if ((pmail->wanted_fields & (MAIL_FETCH_IMAP_ENVELOPE |
					  MAIL_FETCH_HEADER_MD5 |
					  MAIL_FETCH_DATE)) != 0 ||
		 pmail->wanted_headers != NULL)
		str_append(str, "BODY.PEEK[HEADER] ");

	if ((pmail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0)
		str_append(str, "INTERNALDATE ");

	if (str_len(str) == orig_len) {
		/* we don't need to fetch anything */
		return TRUE;
	}

	str_truncate(str, str_len(str) - 1);
	str_append_c(str, ')');

	mbox->cur_fetch_mail = mail;
	imapc_client_mailbox_cmdf(mbox->client_box, imapc_async_stop_callback,
				  mbox->storage, "%1s", str_c(str));
	imapc_client_run(mbox->storage->client);
	mbox->cur_fetch_mail = NULL;
	return TRUE;
}

static int create_temp_fd(struct mail_user *user, const char **path_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	mail_user_set_get_temp_prefix(path, user->set);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		(void)close(fd);
		return -1;
	}
	*path_r = str_c(path);
	return fd;
}

static void
imapc_fetch_stream(struct index_mail *imail, const char *value, bool body)
{
	struct mail *_mail = &imail->mail.mail;
	struct istream *input;
	size_t size = strlen(value);
	const char *path;
	int fd;

	if (imail->data.stream != NULL)
		return;

	fd = create_temp_fd(_mail->box->storage->user, &path);
	if (fd == -1)
		return;
	if (write_full(fd, value, size) < 0) {
		(void)close(fd);
		return;
	}

	imail->data.stream = i_stream_create_fd(fd, 0, TRUE);
	i_stream_set_name(imail->data.stream, path);
	index_mail_set_read_buffer_size(_mail, imail->data.stream);

	if (body) {
		imail->data.physical_size = size;
		imail->data.virtual_size = size;
	}

	if (index_mail_init_stream(imail, NULL, NULL, &input) < 0)
		i_stream_unref(&imail->data.stream);
}

void imapc_fetch_mail_update(struct mail *mail, const struct imap_arg *args)
{
	struct index_mail *imail = (struct index_mail *)mail;
	const char *key, *value;
	unsigned int i;
	time_t t;
	int tz;

	for (i = 0; args[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&args[i], &key) ||
		    args[i+1].type == IMAP_ARG_EOL)
			return;

		if (strcasecmp(key, "BODY[]") == 0) {
			if (!imap_arg_get_nstring(&args[i+1], &value))
				return;
			if (value != NULL)
				imapc_fetch_stream(imail, value, TRUE);
		} else if (strcasecmp(key, "BODY[HEADER]") == 0) {
			if (!imap_arg_get_nstring(&args[i+1], &value))
				return;
			if (value != NULL)
				imapc_fetch_stream(imail, value, FALSE);
		} else if (strcasecmp(key, "INTERNALDATE") == 0) {
			if (!imap_arg_get_astring(&args[i+1], &value) ||
			    !imap_parse_datetime(value, &t, &tz))
				return;
			imail->data.received_date = t;
		}
	}
}
