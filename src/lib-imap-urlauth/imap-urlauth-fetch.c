/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

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
	unsigned int refcount;
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

		bool succeeded:1;
		bool binary_has_nuls:1;
	} pending_reply;

	bool failed:1;
	bool waiting_local:1;
	bool waiting_service:1;
};

static void imap_urlauth_fetch_abort_local(struct imap_urlauth_fetch *ufetch)
{
	struct imap_urlauth_fetch_url *url, *url_next;

	if (ufetch->local_url != NULL) {
		ufetch->pending_requests--;
		imap_msgpart_url_free(&ufetch->local_url);
	}

	i_free_and_null(ufetch->pending_reply.url);
	i_free_and_null(ufetch->pending_reply.bodypartstruct);
	i_free_and_null(ufetch->pending_reply.error);
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
	ufetch->refcount = 1;
	ufetch->uctx = uctx;
	ufetch->callback = callback;
	ufetch->context = context;
	return ufetch;
}

static void imap_urlauth_fetch_ref(struct imap_urlauth_fetch *ufetch)
{
	i_assert(ufetch->refcount > 0);
	ufetch->refcount++;
}

static void imap_urlauth_fetch_unref(struct imap_urlauth_fetch **_ufetch)
{
	struct imap_urlauth_fetch *ufetch = *_ufetch;

	i_assert(ufetch->refcount > 0);

	*_ufetch = NULL;
	if (--ufetch->refcount > 0)
		return;

	ufetch->refcount++;
	imap_urlauth_fetch_abort(ufetch);
	ufetch->refcount--;
	i_assert(ufetch->refcount == 0);

	/* dont leave the connection in limbo; make sure continue is called */
	if (ufetch->waiting_service)
		imap_urlauth_connection_continue(ufetch->uctx->conn);
	i_free(ufetch);
}

void imap_urlauth_fetch_deinit(struct imap_urlauth_fetch **_ufetch)
{
	imap_urlauth_fetch_unref(_ufetch);
}

static void
imap_urlauth_fetch_error(struct imap_urlauth_fetch *ufetch, const char *url,
			 enum imap_urlauth_fetch_flags url_flags,
			 const char *error)
{
	struct imap_urlauth_fetch_reply reply;
	int ret;

	ufetch->pending_requests--;

	i_zero(&reply);
	reply.url = url;
	reply.flags = url_flags;
	reply.succeeded = FALSE;
	reply.error = error;

	T_BEGIN {
		ret = ufetch->callback(&reply, ufetch->pending_requests == 0,
				       ufetch->context);
	} T_END;

	if (ret == 0) {
		ufetch->waiting_local = TRUE;
		ufetch->pending_requests++;
	} else if (ret < 0) {
		imap_urlauth_fetch_fail(ufetch);
	}
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
	struct imap_msgpart_url *mpurl = NULL;
	int ret;

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
	i_zero(&mpresult);
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

	ufetch->pending_requests--;

	if (!success && ret < 0) {
		if (mpurl != NULL)
			imap_msgpart_url_free(&mpurl);
		(void)ufetch->callback(NULL, TRUE, ufetch->context);
		imap_urlauth_fetch_fail(ufetch);
		return;
	}

	i_zero(&reply);
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
		ufetch->waiting_local = TRUE;
		ufetch->pending_requests++;
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

	if (ufetch->waiting_local && reply != NULL) {
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
		ufetch->waiting_service = TRUE;
		return 0;
	}

	ufetch->waiting_local = FALSE;
	ufetch->pending_requests--;

	imap_urlauth_fetch_ref(ufetch);

	if (!ufetch->failed) {
		bool last = ufetch->pending_requests == 0 || reply == NULL;
		ret = ufetch->callback(reply, last, ufetch->context);
	}

	/* report failure only once */
	if (ret < 0 || reply == NULL) {
		if (!ufetch->failed)
			imap_urlauth_fetch_abort_local(ufetch);
		ufetch->failed = TRUE;
	} else if (ret == 0) {
		ufetch->waiting_service = TRUE;
		ufetch->pending_requests++;
	}
	
	imap_urlauth_fetch_unref(&ufetch);
	return ret;
}

int imap_urlauth_fetch_url(struct imap_urlauth_fetch *ufetch, const char *url,
			   enum imap_urlauth_fetch_flags url_flags)
{
	struct imap_urlauth_context *uctx = ufetch->uctx;
	enum imap_url_parse_flags url_parse_flags =
		IMAP_URL_PARSE_ALLOW_URLAUTH;
	struct mail_user *mail_user = uctx->user;
	struct imap_url *imap_url;
	const char *error, *errormsg;

	/* parse the url */
	if (imap_url_parse(url, NULL, url_parse_flags, &imap_url, &error) < 0) {
		errormsg = t_strdup_printf(
			"Failed to fetch URLAUTH \"%s\": %s", url, error);
		e_debug(mail_user->event, "%s", errormsg);
		ufetch->pending_requests++;
		imap_urlauth_fetch_ref(ufetch);
		imap_urlauth_fetch_error(ufetch, url, url_flags, errormsg);
		imap_urlauth_fetch_unref(&ufetch);
		return 1;
	}

	return imap_urlauth_fetch_url_parsed(ufetch, url, imap_url, url_flags);
}

int imap_urlauth_fetch_url_parsed(struct imap_urlauth_fetch *ufetch,
			   const char *url, struct imap_url *imap_url,
			   enum imap_urlauth_fetch_flags url_flags)
{
	struct imap_urlauth_context *uctx = ufetch->uctx;
	struct mail_user *mail_user = uctx->user;
	const char *error, *errormsg;
	int ret = 0;

	ufetch->failed = FALSE;
	ufetch->pending_requests++;

	imap_urlauth_fetch_ref(ufetch);

	/* if access user and target user match, handle fetch request locally */
	if (imap_url->userid != NULL &&
		strcmp(mail_user->username, imap_url->userid) == 0) {

		if (ufetch->waiting_local) {
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
		e_debug(mail_user->event, "%s", errormsg);
		imap_urlauth_fetch_error(ufetch, url, url_flags, errormsg);
		imap_url = NULL;
	}

	/* create request for url */
	if (imap_url != NULL && imap_url->userid != NULL) {
		i_assert(uctx->conn != NULL);
		(void)imap_urlauth_request_new(uctx->conn, imap_url->userid,
				url, url_flags,
				imap_urlauth_fetch_request_callback, ufetch);
		i_assert(uctx->conn != NULL);
		if (imap_urlauth_connection_connect(uctx->conn) < 0)
			ret = -1;
	}
	if (ret >= 0)
		ret = (ufetch->pending_requests > 0 ? 0 : 1);

	imap_urlauth_fetch_unref(&ufetch);
	return ret;
}

static bool imap_urlauth_fetch_do_continue(struct imap_urlauth_fetch *ufetch)
{
	struct imap_urlauth_fetch_url *url, *url_next;
	int ret;

	if (ufetch->failed)
		return FALSE;

	if (!ufetch->waiting_local && !ufetch->waiting_service) {
		/* not currently waiting for anything */
		return ufetch->pending_requests > 0;
	}

	/* we finished a request */
	ufetch->pending_requests--;

	if (!ufetch->waiting_local) {
		/* not waiting for local request handling */
		ufetch->waiting_service = FALSE;
		imap_urlauth_connection_continue(ufetch->uctx->conn);
		return ufetch->pending_requests > 0;
	}

	/* finished local request */
	if (ufetch->local_url != NULL) {
		imap_msgpart_url_free(&ufetch->local_url);
	}
	ufetch->waiting_local = FALSE;

	/* handle pending remote reply */
	if (ufetch->pending_reply.url != NULL) {
		struct imap_urlauth_fetch_reply reply;

		ufetch->pending_requests--;

		i_zero(&reply);
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

		if (ret == 0) {
			ufetch->waiting_service = TRUE;
			ufetch->pending_requests++;
			return TRUE;
		}

		ufetch->waiting_service = FALSE;
		imap_urlauth_connection_continue(ufetch->uctx->conn);
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
		if (ufetch->waiting_local) 
			return TRUE;
		url = url_next;
	}

	return ufetch->pending_requests > 0;
}

bool imap_urlauth_fetch_continue(struct imap_urlauth_fetch *ufetch)
{
	bool pending;

	imap_urlauth_fetch_ref(ufetch);
	pending = imap_urlauth_fetch_do_continue(ufetch);
	imap_urlauth_fetch_unref(&ufetch);

	return pending;
}

bool imap_urlauth_fetch_is_pending(struct imap_urlauth_fetch *ufetch)
{
	return ufetch->pending_requests > 0;
}
