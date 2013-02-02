/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "mail-user.h"
#include "mail-error.h"
#include "mail-storage.h"
#include "imap-url.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth-private.h"
#include "imap-urlauth-fetch.h"
#include "imap-urlauth-connection.h"

struct imap_urlauth_fetch_url {
	struct imap_urlauth_fetch_url *prev, *next;

	char *url;
	enum imap_urlauth_fetch_flags flags;
};

struct imap_urlauth_fetch {
	struct imap_urlauth_context *uctx;

	imap_urlauth_fetch_callback_t *callback;
	void *context;

	/* local urls */
	struct imap_urlauth_fetch_url *local_urls_head, *local_urls_tail;
	struct imap_msgpart_url *local_url;

	unsigned int pending_requests;

	struct {
		char *url;
		enum imap_urlauth_fetch_flags flags;

		struct istream *input;
		uoff_t size;

		char *bodypartstruct;
		char *error;

		unsigned int succeeded:1;
		unsigned int binary_has_nuls:1;
	} pending_reply;

	unsigned int failed:1;
	unsigned int waiting:1;
};

static void imap_urlauth_fetch_abort_local(struct imap_urlauth_fetch *ufetch)
{
	struct imap_urlauth_fetch_url *url, *url_next;

	if (ufetch->local_url != NULL)
		imap_msgpart_url_free(&ufetch->local_url);

	i_free_and_null(ufetch->pending_reply.url);
	i_free_and_null(ufetch->pending_reply.bodypartstruct);
	i_free_and_null(ufetch->pending_reply.error);
	if (ufetch->pending_reply.input != NULL)
		i_stream_unref(&ufetch->pending_reply.input);

	url = ufetch->local_urls_head;
	for (; url != NULL; url = url_next) {
		url_next = url->next;
		i_free(url->url);
		i_free(url);
		ufetch->pending_requests--;
	}
	ufetch->local_urls_head = ufetch->local_urls_tail = NULL;
}

static void imap_urlauth_fetch_abort(struct imap_urlauth_fetch *ufetch)
{
	if (ufetch->pending_requests > 0)
		imap_urlauth_request_abort_by_context(ufetch->uctx->conn, ufetch);

	imap_urlauth_fetch_abort_local(ufetch);

	i_assert(ufetch->pending_requests == 0);
}

static void imap_urlauth_fetch_fail(struct imap_urlauth_fetch *ufetch)
{
	imap_urlauth_fetch_abort(ufetch);
	ufetch->failed = TRUE;
}

struct imap_urlauth_fetch *
imap_urlauth_fetch_init(struct imap_urlauth_context *uctx,
			imap_urlauth_fetch_callback_t *callback, void *context)
{
	struct imap_urlauth_fetch *ufetch;

	ufetch = i_new(struct imap_urlauth_fetch, 1);
	ufetch->uctx = uctx;
	ufetch->callback = callback;
	ufetch->context = context;
	return ufetch;
}

void imap_urlauth_fetch_deinit(struct imap_urlauth_fetch **_ufetch)
{
	struct imap_urlauth_fetch *ufetch = *_ufetch;

	*_ufetch = NULL;

	imap_urlauth_fetch_abort(ufetch);
	i_free(ufetch);
}

static void
imap_urlauth_fetch_error(struct imap_urlauth_fetch *ufetch, const char *url,
			 enum imap_urlauth_fetch_flags url_flags,
			 const char *error)
{
	struct imap_urlauth_fetch_reply reply;
	int ret;

	ufetch->pending_requests--;

	memset(&reply, 0, sizeof(reply));
	reply.url = url;
	reply.flags = url_flags;
	reply.succeeded = FALSE;
	reply.error = error;

	T_BEGIN {
		ret = ufetch->callback(&reply, ufetch->pending_requests == 0,
				       ufetch->context);
	} T_END;

	if (ret == 0)
		ufetch->waiting = TRUE;
	else if (ret < 0)
		imap_urlauth_fetch_fail(ufetch);
}

static void
imap_urlauth_fetch_local(struct imap_urlauth_fetch *ufetch, const char *url,
			 enum imap_urlauth_fetch_flags url_flags,
			 struct imap_url *imap_url)
{
	struct imap_urlauth_fetch_reply reply;
	struct imap_msgpart_open_result mpresult;
	const char *error, *errormsg = NULL, *bpstruct = NULL;
	bool debug = ufetch->uctx->user->mail_debug, success;
	enum mail_error error_code;
	struct imap_msgpart_url *mpurl;
	int ret;

	ufetch->pending_requests--;
	success = TRUE;

	if (debug)
		i_debug("Fetching local URLAUTH %s", url);

	if (url_flags == 0)
		url_flags = IMAP_URLAUTH_FETCH_FLAG_BODY;

	/* fetch URL */
	if (imap_url == NULL) {
		ret = imap_urlauth_fetch(ufetch->uctx, url,
					 &mpurl, &error_code, &error);
	} else {
		ret = imap_urlauth_fetch_parsed(ufetch->uctx, imap_url,
						&mpurl, &error_code, &error);
	}
	if (ret <= 0) {
		if (ret == 0) {
			errormsg = t_strdup_printf("Failed to fetch URLAUTH \"%s\": %s",
						   url, error);
			if (debug)
				i_debug("%s", errormsg);
		}
		success = FALSE;
	}

	/* fetch metadata */
	if (success && (url_flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0)
		imap_msgpart_url_set_decode_to_binary(mpurl);
	if (success &&
	    (url_flags & IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE) != 0) {
		ret = imap_msgpart_url_get_bodypartstructure(mpurl, &bpstruct, &error);
		if (ret <= 0) {
			if (ret == 0) {
				errormsg = t_strdup_printf
					("Failed to read URLAUTH \"%s\": %s",	url, error);
				if (debug)
					i_debug("%s", errormsg);
			}
			success = FALSE;
		}
	}

	/* if requested, read the message part the URL points to */
	memset(&mpresult, 0, sizeof(mpresult));
	if (success && ((url_flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0 ||
			(url_flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0)) {
		ret = imap_msgpart_url_read_part(mpurl, &mpresult, &error);
		if (ret <= 0) {
			if (ret == 0) {
				errormsg = t_strdup_printf
					("Failed to read URLAUTH \"%s\": %s",	url, error);
				if (debug)
					i_debug("%s", errormsg);
			}
			success = FALSE;
		}
	}

	if (debug && success) {
		if (bpstruct != NULL)
			i_debug("Fetched URLAUTH yielded BODYPARTSTRUCTURE (%s)", bpstruct);
		if (mpresult.size == 0 || mpresult.input == NULL)
			i_debug("Fetched URLAUTH yielded empty result");
		else {
			i_debug("Fetched URLAUTH yielded %"PRIuUOFF_T" bytes "
				"of %smessage data", mpresult.size,
				(mpresult.binary_decoded_input_has_nuls ? "binary " : ""));
		}
	}

	if (!success && ret < 0) {
		(void)ufetch->callback(NULL, TRUE, ufetch->context);
		imap_urlauth_fetch_fail(ufetch);
		return;
	}

	memset(&reply, 0, sizeof(reply));
	reply.url = url;
	reply.flags = url_flags;
	reply.error = errormsg;
	reply.succeeded = success;

	reply.bodypartstruct = bpstruct;
	reply.binary_has_nuls = mpresult.binary_decoded_input_has_nuls;
	reply.size = mpresult.size;
	reply.input = mpresult.input;

	ret = ufetch->callback(&reply, ufetch->pending_requests == 0,
			       ufetch->context);
	if (ret == 0) {
		ufetch->local_url = mpurl;
		ufetch->waiting = TRUE;
	} else {
		if (mpurl != NULL)
			imap_msgpart_url_free(&mpurl);
		if (ret < 0)
			imap_urlauth_fetch_fail(ufetch);
	}
}

static int
imap_urlauth_fetch_request_callback(struct imap_urlauth_fetch_reply *reply,
				    void *context)
{
	struct imap_urlauth_fetch *ufetch =
		(struct imap_urlauth_fetch *)context;
	int ret = 1;

	if (ufetch->waiting && reply != NULL) {
		i_assert(ufetch->pending_reply.url == NULL);
		ufetch->pending_reply.url = i_strdup(reply->url);
		ufetch->pending_reply.flags = reply->flags;
		ufetch->pending_reply.bodypartstruct =
			i_strdup(reply->bodypartstruct);
		ufetch->pending_reply.error = i_strdup(reply->error);
		if (reply->input != NULL) {
			ufetch->pending_reply.input = reply->input;
			i_stream_ref(ufetch->pending_reply.input);
		}
		ufetch->pending_reply.size = reply->size;
		ufetch->pending_reply.succeeded = reply->succeeded;
		ufetch->pending_reply.binary_has_nuls = reply->binary_has_nuls;
		return 0;
	}

	ufetch->waiting = FALSE;
	ufetch->pending_requests--;

	if (!ufetch->failed) {
		bool last = ufetch->pending_requests == 0 || reply == NULL;
		ret = ufetch->callback(reply, last, ufetch->context);
	}

	/* report failure only once */
	if (ret < 0 || reply == NULL) {
		if (!ufetch->failed)
			imap_urlauth_fetch_abort_local(ufetch);
		ufetch->failed = TRUE;
	}
	if (ret != 0)
		imap_urlauth_fetch_deinit(&ufetch);
	return ret;
}

int imap_urlauth_fetch_url(struct imap_urlauth_fetch *ufetch, const char *url,
			   enum imap_urlauth_fetch_flags url_flags)
{
	enum imap_url_parse_flags url_parse_flags =
		IMAP_URL_PARSE_ALLOW_URLAUTH;
	struct imap_urlauth_context *uctx = ufetch->uctx;
	struct mail_user *mail_user = uctx->user;
	struct imap_url *imap_url = NULL;
	const char *error, *errormsg;

	ufetch->failed = FALSE;
	ufetch->pending_requests++;

	/* parse the url */
	if (imap_url_parse(url, NULL, url_parse_flags, &imap_url, &error) < 0) {
		errormsg = t_strdup_printf(
			"Failed to fetch URLAUTH \"%s\": %s", url, error);
		if (mail_user->mail_debug)
			i_debug("%s", errormsg);
		imap_urlauth_fetch_error(ufetch, url, url_flags, errormsg);
	
	/* if access user and target user match, handle fetch request locally */
	} else if (strcmp(mail_user->username, imap_url->userid) == 0) {

		if (ufetch->waiting) {
			struct imap_urlauth_fetch_url *url_local;

			url_local = i_new(struct imap_urlauth_fetch_url, 1);
			url_local->url = i_strdup(url);
			url_local->flags = url_flags;

			DLLIST2_APPEND(&ufetch->local_urls_head,
				       &ufetch->local_urls_tail, url_local);
		} else T_BEGIN {
			imap_urlauth_fetch_local(ufetch, url,
						 url_flags, imap_url);
		} T_END;
		imap_url = NULL;
	/* don't try to fetch remote URLs that are already known to fail access */
	} else if (!imap_urlauth_check(uctx, imap_url, TRUE, &error)) {
		errormsg = t_strdup_printf(
			"Failed to fetch URLAUTH \"%s\": %s", url, error);
		if (mail_user->mail_debug)
			i_debug("%s", errormsg);
		imap_urlauth_fetch_error(ufetch, url, url_flags, errormsg);
		imap_url = NULL;
	}

	/* create request for url */
	if (imap_url != NULL && imap_url->userid != NULL) {
		(void)imap_urlauth_request_new(uctx->conn, imap_url->userid,
				url, url_flags,
				imap_urlauth_fetch_request_callback, ufetch);
	}

	if (ufetch->pending_requests > 0) {
		i_assert(uctx->conn != NULL);
		if (imap_urlauth_connection_connect(uctx->conn) < 0)
			return -1;
		return 0;
	}
	return 1;
}

bool imap_urlauth_fetch_continue(struct imap_urlauth_fetch *ufetch)
{
	struct imap_urlauth_fetch_url *url, *url_next;
	int ret;

	if (ufetch->failed)
		return FALSE;

	if (!ufetch->waiting) {
		/* not waiting for local request handling */
		imap_urlauth_connection_continue(ufetch->uctx->conn);
		return ufetch->pending_requests > 0;
	} 

	if (ufetch->local_url != NULL)
		imap_msgpart_url_free(&ufetch->local_url);
	ufetch->waiting = FALSE;

	/* handle pending remote reply */
	if (ufetch->pending_reply.url != NULL) {
		struct imap_urlauth_fetch_reply reply;

		ufetch->pending_requests--;

		memset(&reply, 0, sizeof(reply));
		reply.url = ufetch->pending_reply.url;
		reply.flags = ufetch->pending_reply.flags;
		reply.bodypartstruct = ufetch->pending_reply.bodypartstruct;
		reply.error = ufetch->pending_reply.error;
		reply.input = ufetch->pending_reply.input;
		reply.size = ufetch->pending_reply.size;
		reply.succeeded = ufetch->pending_reply.succeeded;
		reply.binary_has_nuls = ufetch->pending_reply.binary_has_nuls;

		ret = ufetch->callback(&reply, ufetch->pending_requests == 0,
				       ufetch->context);

		if (ufetch->pending_reply.url != NULL)
			i_free(ufetch->pending_reply.url);
		if (ufetch->pending_reply.input != NULL)
			i_stream_unref(&ufetch->pending_reply.input);
		if (ufetch->pending_reply.bodypartstruct != NULL)
			i_free(ufetch->pending_reply.bodypartstruct);
		if (ufetch->pending_reply.error != NULL)
			i_free(ufetch->pending_reply.error);

		if (ret < 0) {
			imap_urlauth_fetch_fail(ufetch);
			return FALSE;
		} 
		
		imap_urlauth_connection_continue(ufetch->uctx->conn);

		if (ret == 0) {
			ufetch->waiting = TRUE;
			return TRUE;
		}
	}

	/* handle pending local urls */
	url = ufetch->local_urls_head;
	while (url != NULL) {
		url_next = url->next;
		T_BEGIN {
			imap_urlauth_fetch_local(ufetch, url->url,
						 url->flags, NULL);
		} T_END;
		DLLIST2_REMOVE(&ufetch->local_urls_head,
			       &ufetch->local_urls_tail, url);
		i_free(url->url);
		i_free(url);
		if (ufetch->waiting) 
			return TRUE;
		url = url_next;
	}

	return ufetch->pending_requests > 0;
}
