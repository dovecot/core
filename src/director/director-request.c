/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "mail-host.h"
#include "user-directory.h"
#include "director.h"
#include "director-request.h"

#define DIRECTOR_REQUEST_TIMEOUT_SECS 30
#define RING_NOCONN_WARNING_DELAY_MSECS (2*1000)

struct director_request {
	struct director *dir;

	time_t create_time;
	unsigned int username_hash;

	director_request_callback *callback;
	void *context;
};

static const char *
director_request_get_timeout_error(struct director_request *request)
{
	string_t *str = t_str_new(128);
	unsigned int secs;

	str_printfa(str, "Timeout - queued for %u secs (",
		    (unsigned int)(ioloop_time - request->create_time));

	if (request->dir->ring_last_sync_time == 0)
		str_append(str, "Ring has never been synced");
	else {
		secs =ioloop_time - request->dir->ring_last_sync_time;
		if (request->dir->ring_synced)
			str_printfa(str, "Ring synced for %u secs", secs);
		else
			str_printfa(str, "Ring not synced for %u secs", secs);
	}
	str_append_c(str, ')');
	return str_c(str);
}

static void director_request_timeout(struct director *dir)
{
	struct director_request **requestp, *request;
	const char *errormsg;

	while (array_count(&dir->pending_requests) > 0) {
		requestp = array_idx_modifiable(&dir->pending_requests, 0);
		request = *requestp;

		if (request->create_time +
		    DIRECTOR_REQUEST_TIMEOUT_SECS > ioloop_time)
			break;

		array_delete(&dir->pending_requests, 0, 1);
		errormsg = director_request_get_timeout_error(request);
		T_BEGIN {
			request->callback(NULL, errormsg, request->context);
		} T_END;
		i_free(request);
	}

	if (array_count(&dir->pending_requests) == 0 && dir->to_request != NULL)
		timeout_remove(&dir->to_request);
}

void director_request(struct director *dir, const char *username,
		      director_request_callback *callback, void *context)
{
	struct director_request *request;
	unsigned int username_hash =
		user_directory_get_username_hash(dir->users, username);

	request = i_new(struct director_request, 1);
	request->dir = dir;
	request->create_time = ioloop_time;
	request->username_hash = username_hash;
	request->callback = callback;
	request->context = context;

	if (director_request_continue(request))
		return;

	/* need to queue it */
	if (dir->to_request == NULL) {
		dir->to_request =
			timeout_add(DIRECTOR_REQUEST_TIMEOUT_SECS * 1000,
				    director_request_timeout, dir);
	}
	array_append(&dir->pending_requests, &request, 1);
}

static void ring_noconn_warning(struct director *dir)
{
	if (!dir->ring_handshaked) {
		i_warning("Delaying all requests "
			  "until all directors have connected");
	} else {
		i_warning("Delaying new user requests until ring is synced");
	}
	dir->ring_handshake_warning_sent = TRUE;
	timeout_remove(&dir->to_handshake_warning);
}

static void ring_log_delayed_warning(struct director *dir)
{
	if (dir->ring_handshake_warning_sent ||
	    dir->to_handshake_warning != NULL)
		return;

	dir->to_handshake_warning = timeout_add(RING_NOCONN_WARNING_DELAY_MSECS,
						ring_noconn_warning, dir);
}

bool director_request_continue(struct director_request *request)
{
	struct director *dir = request->dir;
	struct mail_host *host;
	struct user *user;

	if (!dir->ring_handshaked) {
		/* delay requests until ring handshaking is complete */
		ring_log_delayed_warning(dir);
		return FALSE;
	}

	user = user_directory_lookup(dir->users, request->username_hash);
	if (user != NULL) {
		if (user->kill_state != USER_KILL_STATE_NONE) {
			/* delay processing this user's connections until
			   its existing connections have been killed */
			return FALSE;
		}
		user_directory_refresh(dir->users, user);
	} else {
		if (!dir->ring_synced) {
			/* delay adding new users until ring is again synced */
			ring_log_delayed_warning(dir);
			return FALSE;
		}
		host = mail_host_get_by_hash(dir->mail_hosts,
					     request->username_hash);
		if (host == NULL) {
			/* all hosts have been removed */
			return FALSE;
		}
		user = user_directory_add(dir->users, request->username_hash,
					  host, ioloop_time);
	}

	director_update_user(dir, dir->self_host, user);
	T_BEGIN {
		request->callback(&user->host->ip, NULL, request->context);
	} T_END;
	i_free(request);
	return TRUE;
}
