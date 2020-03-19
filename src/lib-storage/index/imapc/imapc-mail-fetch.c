/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-concat.h"
#include "istream-header-filter.h"
#include "message-header-parser.h"
#include "imap-arg.h"
#include "imap-date.h"
#include "imap-quote.h"
#include "imap-bodystructure.h"
#include "imap-resp-code.h"
#include "imapc-mail.h"
#include "imapc-storage.h"

static void imapc_mail_set_failure(struct imapc_mail *mail,
				   const struct imapc_command_reply *reply)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(mail->imail.mail.mail.box);

	mail->last_fetch_reply = p_strdup(mail->imail.mail.pool, reply->text_full);

	switch (reply->state) {
	case IMAPC_COMMAND_STATE_OK:
		break;
	case IMAPC_COMMAND_STATE_NO:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS)) {
			/* fetch-fix-broken-mails feature disabled -
			   fail any mails with missing replies */
			break;
		}
		if (reply->resp_text_key != NULL &&
		    (strcasecmp(reply->resp_text_key, IMAP_RESP_CODE_SERVERBUG) == 0 ||
		     strcasecmp(reply->resp_text_key, IMAP_RESP_CODE_LIMIT) == 0)) {
			/* this is a temporary error, retrying should work.
			   Yahoo sends * BYE +
			   NO [LIMIT] UID FETCH Rate limit hit. */
		} else {
			/* hopefully this is a permanent failure */
			mail->fetch_ignore_if_missing = TRUE;
		}
		break;
	case IMAPC_COMMAND_STATE_BAD:
	case IMAPC_COMMAND_STATE_DISCONNECTED:
	case IMAPC_COMMAND_STATE_AUTH_FAILED:
		mail->fetch_failed = TRUE;
		break;
	}
}

static void
imapc_mail_fetch_callback(const struct imapc_command_reply *reply,
			  void *context)
{
	struct imapc_fetch_request *request = context;
	struct imapc_fetch_request *const *requests;
	struct imapc_mail *const *mailp;
	struct imapc_mailbox *mbox = NULL;
	unsigned int i, count;

	array_foreach(&request->mails, mailp) {
		struct imapc_mail *mail = *mailp;

		i_assert(mail->fetch_count > 0);
		imapc_mail_set_failure(mail, reply);
		if (--mail->fetch_count == 0)
			mail->fetching_fields = 0;
		mbox = IMAPC_MAILBOX(mail->imail.mail.mail.box);
	}
	i_assert(mbox != NULL);

	requests = array_get(&mbox->fetch_requests, &count);
	for (i = 0; i < count; i++) {
		if (requests[i] == request) {
			array_delete(&mbox->fetch_requests, i, 1);
			break;
		}
	}
	i_assert(i < count);

	array_free(&request->mails);
	i_free(request);

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS,
					    reply);
	} else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED) {
		/* The disconnection message was already logged */
		mail_storage_set_internal_error(&mbox->storage->storage);
	} else {
		mailbox_set_critical(&mbox->box,
			"imapc: Mail FETCH failed: %s", reply->text_full);
	}
	imapc_client_stop(mbox->storage->client->client);
}

static bool
headers_have_subset(const char *const *superset, const char *const *subset)
{
	unsigned int i;

	if (superset == NULL)
		return FALSE;
	if (subset != NULL) {
		for (i = 0; subset[i] != NULL; i++) {
			if (!str_array_icase_find(superset, subset[i]))
				return FALSE;
		}
	}
	return TRUE;
}

static const char *const *
headers_merge(pool_t pool, const char *const *h1, const char *const *h2)
{
	ARRAY_TYPE(const_string) headers;
	const char *value;
	unsigned int i;

	p_array_init(&headers, pool, 16);
	if (h1 != NULL) {
		for (i = 0; h1[i] != NULL; i++) {
			value = p_strdup(pool, h1[i]);
			array_push_back(&headers, &value);
		}
	}
	if (h2 != NULL) {
		for (i = 0; h2[i] != NULL; i++) {
			if (h1 == NULL || !str_array_icase_find(h1, h2[i])) {
				value = p_strdup(pool, h2[i]);
				array_push_back(&headers, &value);
			}
		}
	}
	array_append_zero(&headers);
	return array_front(&headers);
}

static bool
imapc_mail_try_merge_fetch(struct imapc_mailbox *mbox, string_t *str)
{
	const char *s1 = str_c(str);
	const char *s2 = str_c(mbox->pending_fetch_cmd);
	const char *p1, *p2;

	i_assert(str_begins(s1, "UID FETCH "));
	i_assert(str_begins(s2, "UID FETCH "));

	/* skip over UID range */
	p1 = strchr(s1+10, ' ');
	p2 = strchr(s2+10, ' ');

	if (null_strcmp(p1, p2) != 0)
		return FALSE;
	/* append the new UID to the pending FETCH UID range */
	str_truncate(str, p1-s1);
	str_insert(mbox->pending_fetch_cmd, p2-s2, ",");
	str_insert(mbox->pending_fetch_cmd, p2-s2+1, str_c(str) + 10);
	return TRUE;
}

static void
imapc_mail_delayed_send_or_merge(struct imapc_mail *mail, string_t *str)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(mail->imail.mail.mail.box);

	if (mbox->pending_fetch_request != NULL &&
	    !imapc_mail_try_merge_fetch(mbox, str)) {
		/* send the previous FETCH and create a new one */
		imapc_mail_fetch_flush(mbox);
	}
	if (mbox->pending_fetch_request == NULL) {
		mbox->pending_fetch_request =
			i_new(struct imapc_fetch_request, 1);
		i_array_init(&mbox->pending_fetch_request->mails, 4);
		i_assert(mbox->pending_fetch_cmd->used == 0);
		str_append_str(mbox->pending_fetch_cmd, str);
	}
	array_push_back(&mbox->pending_fetch_request->mails, &mail);

	if (mbox->to_pending_fetch_send == NULL &&
	    array_count(&mbox->pending_fetch_request->mails) >
	    			mbox->box.storage->set->mail_prefetch_count) {
		/* we're now prefetching the maximum number of mails. this
		   most likely means that we need to flush out the command now
		   before sending anything else. delay it a little bit though
		   in case the sending code doesn't actually use
		   mail_prefetch_count and wants to fetch more.

		   note that we don't want to add this timeout too early,
		   because we want to optimize the maximum number of messages
		   placed into a single FETCH. even without timeout the command
		   gets flushed by imapc_mail_fetch() call. */
		mbox->to_pending_fetch_send =
			timeout_add_short(0, imapc_mail_fetch_flush, mbox);
	}
}

static int
imapc_mail_send_fetch(struct mail *_mail, enum mail_fetch_field fields,
		      const char *const *headers)
{
	struct imapc_mail *mail = IMAPC_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct mail_index_view *view;
	string_t *str;
	uint32_t seq;
	unsigned int i;

	i_assert(headers == NULL ||
		 IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_HEADERS));

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER) {
		mail_set_aborted(_mail);
		return -1;
	}
	_mail->mail_stream_opened = TRUE;

	/* drop any fields that we may already be fetching currently */
	fields &= ~mail->fetching_fields;
	if (headers_have_subset(mail->fetching_headers, headers))
		headers = NULL;
	if (fields == 0 && headers == NULL)
		return mail->fetch_sent ? 0 : 1;

	if (!_mail->saving) {
		/* if we already know that the mail is expunged,
		   don't try to FETCH it */
		view = mbox->delayed_sync_view != NULL ?
			mbox->delayed_sync_view : mbox->box.view;
		if (!mail_index_lookup_seq(view, _mail->uid, &seq) ||
		    mail_index_is_expunged(view, seq)) {
			mail_set_expunged(_mail);
			return -1;
		}
	} else if (mbox->client_box == NULL) {
		/* opened as save-only. we'll need to fetch the mail,
		   so actually SELECT/EXAMINE the mailbox */
		i_assert(mbox->box.opened);

		if (imapc_mailbox_select(mbox) < 0)
			return -1;
	}

	if ((fields & MAIL_FETCH_STREAM_BODY) != 0)
		fields |= MAIL_FETCH_STREAM_HEADER;

	str = t_str_new(64);
	str_printfa(str, "UID FETCH %u (", _mail->uid);
	if ((fields & MAIL_FETCH_RECEIVED_DATE) != 0)
		str_append(str, "INTERNALDATE ");
	if ((fields & MAIL_FETCH_SAVE_DATE) != 0) {
		i_assert(HAS_ALL_BITS(mbox->capabilities,
				      IMAPC_CAPABILITY_SAVEDATE));
		str_append(str, "SAVEDATE ");
	}
	if ((fields & (MAIL_FETCH_PHYSICAL_SIZE | MAIL_FETCH_VIRTUAL_SIZE)) != 0)
		str_append(str, "RFC822.SIZE ");
	if ((fields & MAIL_FETCH_GUID) != 0) {
		str_append(str, mbox->guid_fetch_field_name);
		str_append_c(str, ' ');
	}
	if ((fields & MAIL_FETCH_IMAP_BODY) != 0)
		str_append(str, "BODY ");
	if ((fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0)
		str_append(str, "BODYSTRUCTURE ");

	if ((fields & MAIL_FETCH_STREAM_BODY) != 0) {
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_ZIMBRA_WORKAROUNDS))
			str_append(str, "BODY.PEEK[] ");
		else {
			/* BODY.PEEK[] can return different headers than
			   BODY.PEEK[HEADER] (e.g. invalid 8bit chars replaced
			   with '?' in HEADER) - this violates IMAP protocol
			   and messes up dsync since it sometimes fetches the
			   full body and sometimes only the headers. */
			str_append(str, "BODY.PEEK[HEADER] BODY.PEEK[TEXT] ");
		}
		fields |= MAIL_FETCH_STREAM_HEADER;
	} else if ((fields & MAIL_FETCH_STREAM_HEADER) != 0)
		str_append(str, "BODY.PEEK[HEADER] ");
	else if (headers != NULL) {
		mail->fetching_headers =
			headers_merge(mail->imail.mail.data_pool, headers,
				      mail->fetching_headers);
		str_append(str, "BODY.PEEK[HEADER.FIELDS (");
		for (i = 0; mail->fetching_headers[i] != NULL; i++) {
			if (i > 0)
				str_append_c(str, ' ');
			imap_append_astring(str, mail->fetching_headers[i]);
		}
		str_append(str, ")] ");
		mail->header_list_fetched = FALSE;
	}
	str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	mail->fetching_fields |= fields;
	mail->fetch_count++;
	mail->fetch_sent = FALSE;
	mail->fetch_failed = FALSE;

	imapc_mail_delayed_send_or_merge(mail, str);
	return 1;
}

static void imapc_mail_cache_get(struct imapc_mail *mail,
				 struct imapc_mail_cache *cache)
{
	if (mail->body_fetched)
		return;

	if (cache->fd != -1) {
		mail->fd = cache->fd;
		mail->imail.data.stream = i_stream_create_fd(mail->fd, 0);
		cache->fd = -1;
	} else if (cache->buf != NULL) {
		mail->body = cache->buf;
		mail->imail.data.stream =
			i_stream_create_from_data(mail->body->data,
						  mail->body->used);
		cache->buf = NULL;
	} else {
		return;
	}
	mail->header_fetched = TRUE;
	mail->body_fetched = TRUE;
	imapc_mail_init_stream(mail);
}

static enum mail_fetch_field
imapc_mail_get_wanted_fetch_fields(struct imapc_mail *mail)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(mail->imail.mail.mail.box);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields = 0;

	if ((data->wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0 &&
	    data->received_date == (time_t)-1)
		fields |= MAIL_FETCH_RECEIVED_DATE;
	if ((data->wanted_fields & MAIL_FETCH_SAVE_DATE) != 0 &&
	    data->save_date == (time_t)-1) {
		if (HAS_ALL_BITS(mbox->capabilities, IMAPC_CAPABILITY_SAVEDATE))
			fields |= MAIL_FETCH_SAVE_DATE;
		else
			fields |= MAIL_FETCH_RECEIVED_DATE;
	}
	if ((data->wanted_fields & (MAIL_FETCH_PHYSICAL_SIZE |
				    MAIL_FETCH_VIRTUAL_SIZE)) != 0 &&
	    data->physical_size == (uoff_t)-1 &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE))
		fields |= MAIL_FETCH_PHYSICAL_SIZE | MAIL_FETCH_VIRTUAL_SIZE;
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODY) != 0 &&
	    data->body == NULL &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE))
		fields |= MAIL_FETCH_IMAP_BODY;
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0 &&
	    data->bodystructure == NULL &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE))
		fields |= MAIL_FETCH_IMAP_BODYSTRUCTURE;
	if ((data->wanted_fields & MAIL_FETCH_GUID) != 0 &&
	    data->guid == NULL && mbox->guid_fetch_field_name != NULL)
		fields |= MAIL_FETCH_GUID;

	if (data->stream == NULL && data->access_part != 0) {
		if ((data->access_part & (READ_BODY | PARSE_BODY)) != 0)
			fields |= MAIL_FETCH_STREAM_BODY;
		fields |= MAIL_FETCH_STREAM_HEADER;
	}
	return fields;
}

void imapc_mail_try_init_stream_from_cache(struct imapc_mail *mail)
{
	struct mail *_mail = &mail->imail.mail.mail;
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);

	if (mbox->prev_mail_cache.uid == _mail->uid)
		imapc_mail_cache_get(mail, &mbox->prev_mail_cache);
}

bool imapc_mail_prefetch(struct mail *_mail)
{
	struct imapc_mail *mail = IMAPC_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields;
	const char *const *headers = NULL;

	/* try to get as much from cache as possible */
	imapc_mail_update_access_parts(&mail->imail);
	/* If mail is already cached we can avoid re-FETCHing the mail.
	   However, don't initialize the stream if we don't actually want to
	   access the mail. */
	if (mail->imail.data.access_part != 0)
		imapc_mail_try_init_stream_from_cache(mail);

	fields = imapc_mail_get_wanted_fetch_fields(mail);
	if (data->wanted_headers != NULL && data->stream == NULL &&
	    (fields & MAIL_FETCH_STREAM_HEADER) == 0 &&
	    !imapc_mail_has_headers_in_cache(&mail->imail, data->wanted_headers)) {
		/* fetch specific headers */
		if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_HEADERS))
			headers = data->wanted_headers->name;
		else
			fields |= MAIL_FETCH_STREAM_HEADER;
	}
	if (fields != 0 || headers != NULL) T_BEGIN {
		if (imapc_mail_send_fetch(_mail, fields, headers) > 0)
			mail->imail.data.prefetch_sent = TRUE;
	} T_END;
	return !mail->imail.data.prefetch_sent;
}

static bool
imapc_mail_have_fields(struct imapc_mail *imail, enum mail_fetch_field fields)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(imail->imail.mail.mail.box);

	if ((fields & MAIL_FETCH_RECEIVED_DATE) != 0) {
		if (imail->imail.data.received_date == (time_t)-1)
			return FALSE;
		fields &= ~MAIL_FETCH_RECEIVED_DATE;
	}
	if ((fields & MAIL_FETCH_SAVE_DATE) != 0) {
		i_assert(HAS_ALL_BITS(mbox->capabilities,
				      IMAPC_CAPABILITY_SAVEDATE));
		if (imail->imail.data.save_date == (time_t)-1)
			return FALSE;
		fields &= ~MAIL_FETCH_SAVE_DATE;
	}
	if ((fields & (MAIL_FETCH_PHYSICAL_SIZE | MAIL_FETCH_VIRTUAL_SIZE)) != 0) {
		if (imail->imail.data.physical_size == (uoff_t)-1)
			return FALSE;
		fields &= ~(MAIL_FETCH_PHYSICAL_SIZE | MAIL_FETCH_VIRTUAL_SIZE);
	}
	if ((fields & MAIL_FETCH_GUID) != 0) {
		if (imail->imail.data.guid == NULL)
			return FALSE;
		fields &= ~MAIL_FETCH_GUID;
	}
	if ((fields & MAIL_FETCH_IMAP_BODY) != 0) {
		if (imail->imail.data.body == NULL)
			return FALSE;
		fields &= ~MAIL_FETCH_IMAP_BODY;
	}
	if ((fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0) {
		if (imail->imail.data.bodystructure == NULL)
			return FALSE;
		fields &= ~MAIL_FETCH_IMAP_BODYSTRUCTURE;
	}
	if ((fields & (MAIL_FETCH_STREAM_HEADER |
		       MAIL_FETCH_STREAM_BODY)) != 0) {
		if (imail->imail.data.stream == NULL)
			return FALSE;
		fields &= ~(MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY);
	}
	i_assert(fields == 0);
	return TRUE;
}

int imapc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields,
		     const char *const *headers)
{
	struct imapc_mail *imail = IMAPC_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	int ret;

	if ((fields & MAIL_FETCH_GUID) != 0 &&
	    mbox->guid_fetch_field_name == NULL) {
		mail_storage_set_error(_mail->box->storage,
			MAIL_ERROR_NOTPOSSIBLE,
			"Message GUID not available in this server");
		return -1;
	}
	if (_mail->saving) {
		mail_storage_set_error(_mail->box->storage,
			MAIL_ERROR_NOTPOSSIBLE,
			"Attempting to issue FETCH for a mail not yet committed");
		return -1;
	}

	fields |= imapc_mail_get_wanted_fetch_fields(imail);
	T_BEGIN {
		ret = imapc_mail_send_fetch(_mail, fields, headers);
	} T_END;
	if (ret < 0)
		return -1;

	/* we'll continue waiting until we've got all the fields we wanted,
	   or until all FETCH replies have been received (i.e. some FETCHes
	   failed) */
	if (ret > 0)
		imapc_mail_fetch_flush(mbox);
	while (imail->fetch_count > 0 &&
	       (!imapc_mail_have_fields(imail, fields) ||
		!imail->header_list_fetched)) {
		imapc_mailbox_run_nofetch(mbox);
	}
	if (imail->fetch_failed) {
		mail_storage_set_internal_error(&mbox->storage->storage);
		return -1;
	}
	return 0;
}

void imapc_mail_fetch_flush(struct imapc_mailbox *mbox)
{
	struct imapc_command *cmd;
	struct imapc_mail *const *mailp;

	if (mbox->pending_fetch_request == NULL) {
		i_assert(mbox->to_pending_fetch_send == NULL);
		return;
	}

	array_foreach(&mbox->pending_fetch_request->mails, mailp)
		(*mailp)->fetch_sent = TRUE;

	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_mail_fetch_callback,
				       mbox->pending_fetch_request);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	array_push_back(&mbox->fetch_requests, &mbox->pending_fetch_request);

	imapc_command_send(cmd, str_c(mbox->pending_fetch_cmd));

	mbox->pending_fetch_request = NULL;
	timeout_remove(&mbox->to_pending_fetch_send);
	str_truncate(mbox->pending_fetch_cmd, 0);
}

static bool imapc_find_lfile_arg(const struct imapc_untagged_reply *reply,
				 const struct imap_arg *arg, int *fd_r)
{
	const struct imap_arg *list;
	unsigned int i, count;

	for (i = 0; i < reply->file_args_count; i++) {
		const struct imapc_arg_file *farg = &reply->file_args[i];

		if (farg->parent_arg == arg->parent &&
		    imap_arg_get_list_full(arg->parent, &list, &count) &&
		    farg->list_idx < count && &list[farg->list_idx] == arg) {
			*fd_r = farg->fd;
			return TRUE;
		}
	}
	return FALSE;
}

static void imapc_stream_filter(struct istream **input)
{
	static const char *imapc_hide_headers[] = {
		/* Added by MS Exchange 2010 when \Flagged flag is set.
		   This violates IMAP guarantee of messages being immutable. */
		"X-Message-Flag"
	};
	struct istream *filter_input;

	filter_input = i_stream_create_header_filter(*input,
		HEADER_FILTER_EXCLUDE,
		imapc_hide_headers, N_ELEMENTS(imapc_hide_headers),
		*null_header_filter_callback, NULL);
	i_stream_unref(input);
	*input = filter_input;
}

void imapc_mail_init_stream(struct imapc_mail *mail)
{
	struct index_mail *imail = &mail->imail;
	struct mail *_mail = &imail->mail.mail;
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct istream *input;
	uoff_t size;
	int ret;

	i_stream_set_name(imail->data.stream,
			  t_strdup_printf("imapc mail uid=%u", _mail->uid));
	index_mail_set_read_buffer_size(_mail, imail->data.stream);

	if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE)) {
		/* enable filtering only when we're not passing through
		   RFC822.SIZE. otherwise we'll get size mismatches. */
		imapc_stream_filter(&imail->data.stream);
	}
	if (imail->mail.v.istream_opened != NULL) {
		if (imail->mail.v.istream_opened(_mail,
						 &imail->data.stream) < 0) {
			index_mail_close_streams(imail);
			return;
		}
	}
	ret = i_stream_get_size(imail->data.stream, TRUE, &size);
	if (ret < 0) {
		index_mail_close_streams(imail);
		return;
	}
	i_assert(ret != 0);
	/* Once message body is fetched, we can be sure of what its size is.
	   If we had already received RFC822.SIZE, overwrite it here in case
	   it's wrong. Also in more special cases the RFC822.SIZE may be
	   smaller than the fetched message header. In this case change the
	   size as well, otherwise reading via istream-mail will fail. */
	if (mail->body_fetched || imail->data.physical_size < size) {
		if (mail->body_fetched) {
			imail->data.inexact_total_sizes = FALSE;
			/* Don't trust any existing virtual_size. Also don't
			   set it to size, because there's no guarantees about
			   the content having proper CRLF newlines, especially
			   not if istream_opened() has changed the stream. */
			imail->data.virtual_size = (uoff_t)-1;
		}
		imail->data.physical_size = size;
	}

	imail->data.stream_has_only_header = !mail->body_fetched;
	if (index_mail_init_stream(imail, NULL, NULL, &input) < 0)
		index_mail_close_streams(imail);
}

static void
imapc_fetch_stream(struct imapc_mail *mail,
		   const struct imapc_untagged_reply *reply,
		   const struct imap_arg *arg,
		   bool have_header, bool have_body)
{
	struct index_mail *imail = &mail->imail;
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(imail->mail.mail.box);
	struct istream *hdr_stream = NULL;
	const char *value;
	int fd;

	if (imail->data.stream != NULL) {
		i_assert(mail->header_fetched);
		if (mail->body_fetched || !have_body)
			return;
		if (have_header) {
			/* replace the existing stream */
		} else if (mail->fd == -1) {
			/* append this body stream to the existing
			   header stream */
			hdr_stream = imail->data.stream;
			i_stream_ref(hdr_stream);
		} else {
			/* append this body stream to the existing
			   header stream. we'll need to recreate the stream
			   with autoclosed fd. */
			if (lseek(mail->fd, 0, SEEK_SET) < 0)
				i_error("lseek(imapc) failed: %m");
			hdr_stream = i_stream_create_fd_autoclose(&mail->fd, 0);
		}
		index_mail_close_streams(imail);
		i_close_fd(&mail->fd);
	} else {
		if (!have_header) {
			/* BODY.PEEK[TEXT] received - we can't currently handle
			   this before receiving BODY.PEEK[HEADER] reply */
			return;
		}
	}

	if (arg->type == IMAP_ARG_LITERAL_SIZE) {
		if (!imapc_find_lfile_arg(reply, arg, &fd)) {
			i_stream_unref(&hdr_stream);
			return;
		}
		if ((fd = dup(fd)) == -1) {
			i_error("dup() failed: %m");
			i_stream_unref(&hdr_stream);
			return;
		}
		mail->fd = fd;
		imail->data.stream = i_stream_create_fd(fd, 0);
	} else {
		if (!imap_arg_get_nstring(arg, &value))
			value = NULL;
		if (value == NULL ||
		    (value[0] == '\0' &&
		     IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED))) {
			mail_set_expunged(&imail->mail.mail);
			i_stream_unref(&hdr_stream);
			return;
		}
		if (mail->body == NULL) {
			mail->body = buffer_create_dynamic(default_pool,
							   arg->str_len + 1);
		} else if (!have_header && hdr_stream != NULL) {
			/* header is already in the buffer - add body now
			   without destroying the existing header data */
			i_stream_unref(&hdr_stream);
		} else {
			buffer_set_used_size(mail->body, 0);
		}
		buffer_append(mail->body, value, arg->str_len);
		imail->data.stream = i_stream_create_from_data(mail->body->data,
							       mail->body->used);
	}
	if (have_header)
		mail->header_fetched = TRUE;
	mail->body_fetched = have_body;

	if (hdr_stream != NULL) {
		struct istream *inputs[3];

		inputs[0] = hdr_stream;
		inputs[1] = imail->data.stream;
		inputs[2] = NULL;
		imail->data.stream = i_stream_create_concat(inputs);
		i_stream_unref(&inputs[0]);
		i_stream_unref(&inputs[1]);
	}

	imapc_mail_init_stream(mail);
}

static void
imapc_fetch_header_stream(struct imapc_mail *mail,
			  const struct imapc_untagged_reply *reply,
			  const struct imap_arg *args)
{
	const enum message_header_parser_flags hdr_parser_flags =
		MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
		MESSAGE_HEADER_PARSER_FLAG_DROP_CR;
	const struct imap_arg *hdr_list;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	ARRAY_TYPE(const_string) hdr_arr;
	const char *value;
	int ret, fd;

	if (!imap_arg_get_list(args, &hdr_list))
		return;
	if (!imap_arg_atom_equals(args+1, "]"))
		return;
	args += 2;

	/* see if this is reply to the latest headers list request
	   (parse it even if it's not) */
	t_array_init(&hdr_arr, 16);
	while (imap_arg_get_astring(hdr_list, &value)) {
		array_push_back(&hdr_arr, &value);
		hdr_list++;
	}
	if (hdr_list->type != IMAP_ARG_EOL)
		return;
	array_append_zero(&hdr_arr);

	if (headers_have_subset(array_front(&hdr_arr), mail->fetching_headers))
		mail->header_list_fetched = TRUE;

	if (args->type == IMAP_ARG_LITERAL_SIZE) {
		if (!imapc_find_lfile_arg(reply, args, &fd))
			return;
		input = i_stream_create_fd(fd, 0);
	} else {
		if (!imap_arg_get_nstring(args, &value))
			return;
		if (value == NULL) {
			mail_set_expunged(&mail->imail.mail.mail);
			return;
		}
		input = i_stream_create_from_data(value, args->str_len);
	}

	headers_ctx = mailbox_header_lookup_init(mail->imail.mail.mail.box,
						 array_front(&hdr_arr));
	index_mail_parse_header_init(&mail->imail, headers_ctx);

	parser = message_parse_header_init(input, NULL, hdr_parser_flags);
	while ((ret = message_parse_header_next(parser, &hdr)) > 0)
		index_mail_parse_header(NULL, hdr, &mail->imail);
	i_assert(ret != 0);
	index_mail_parse_header(NULL, NULL, &mail->imail);
	message_parse_header_deinit(&parser);

	mailbox_header_lookup_unref(&headers_ctx);
	i_stream_destroy(&input);
}

static const char *
imapc_args_to_bodystructure(struct imapc_mail *mail,
			    const struct imap_arg *list_arg, bool extended)
{
	const struct imap_arg *args;
	struct message_part *parts = NULL;
	const char *ret, *error;
	pool_t pool;

	if (!imap_arg_get_list(list_arg, &args)) {
		mail_set_critical(&mail->imail.mail.mail,
			"imapc: Server sent invalid BODYSTRUCTURE parameters");
		return NULL;
	}

	pool = pool_alloconly_create("imap bodystructure", 1024);
	if (imap_bodystructure_parse_args(args, pool, &parts, &error) < 0) {
		mail_set_critical(&mail->imail.mail.mail,
			"imapc: Server sent invalid BODYSTRUCTURE: %s", error);
		ret = NULL;
	} else {
		string_t *str = t_str_new(128);
		imap_bodystructure_write(parts, str, extended);
		ret = p_strdup(mail->imail.mail.data_pool, str_c(str));
	}
	pool_unref(&pool);
	return ret;
}

void imapc_mail_fetch_update(struct imapc_mail *mail,
			     const struct imapc_untagged_reply *reply,
			     const struct imap_arg *args)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(mail->imail.mail.mail.box);
	const char *key, *value;
	unsigned int i;
	uoff_t size;
	time_t t;
	int tz;
	bool match = FALSE;

	for (i = 0; args[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&args[i], &key) ||
		    args[i+1].type == IMAP_ARG_EOL)
			break;

		if (strcasecmp(key, "BODY[]") == 0) {
			imapc_fetch_stream(mail, reply, &args[i+1], TRUE, TRUE);
			match = TRUE;
		} else if (strcasecmp(key, "BODY[HEADER]") == 0) {
			imapc_fetch_stream(mail, reply, &args[i+1], TRUE, FALSE);
			match = TRUE;
		} else if (strcasecmp(key, "BODY[TEXT]") == 0) {
			imapc_fetch_stream(mail, reply, &args[i+1], FALSE, TRUE);
			match = TRUE;
		} else if (strcasecmp(key, "BODY[HEADER.FIELDS") == 0) {
			imapc_fetch_header_stream(mail, reply, &args[i+1]);
			match = TRUE;
		} else if (strcasecmp(key, "INTERNALDATE") == 0) {
			if (imap_arg_get_astring(&args[i+1], &value) &&
			    imap_parse_datetime(value, &t, &tz)) {
				mail->imail.data.received_date = t;
				if (HAS_NO_BITS(mbox->capabilities,
						 IMAPC_CAPABILITY_SAVEDATE))
					mail->imail.data.save_date = t;
			}
			match = TRUE;
		} else if (strcasecmp(key, "SAVEDATE") == 0) {
			if (imap_arg_get_astring(&args[i+1], &value)) {
				if (strcasecmp(value, "NIL") == 0)
					mail->imail.data.save_date = 0;
				else if (imap_parse_datetime(value, &t, &tz))
					mail->imail.data.save_date = t;
			}
			match = TRUE;
		} else if (strcasecmp(key, "BODY") == 0) {
			if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE)) {
				mail->imail.data.body =
					imapc_args_to_bodystructure(mail, &args[i+1], FALSE);
			}
			match = TRUE;
		} else if (strcasecmp(key, "BODYSTRUCTURE") == 0) {
			if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE)) {
				mail->imail.data.bodystructure =
					imapc_args_to_bodystructure(mail, &args[i+1], TRUE);
			}
			match = TRUE;
		} else if (strcasecmp(key, "RFC822.SIZE") == 0) {
			if (imap_arg_get_atom(&args[i+1], &value) &&
			    str_to_uoff(value, &size) == 0 &&
			    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE)) {
				mail->imail.data.physical_size = size;
				mail->imail.data.virtual_size = size;
				mail->imail.data.inexact_total_sizes = TRUE;
			}
			match = TRUE;
		} else if (strcasecmp(key, "X-GM-MSGID") == 0 ||
			   strcasecmp(key, "X-GUID") == 0) {
			if (imap_arg_get_astring(&args[i+1], &value)) {
				mail->imail.data.guid =
					p_strdup(mail->imail.mail.pool, value);
			}
			match = TRUE;
		}
	}
	if (!match) {
		/* this is only a FETCH FLAGS update for the wanted mail */
	} else {
		imapc_client_stop(mbox->storage->client->client);
	}
}
