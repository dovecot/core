/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "mail-host.h"
#include "director.h"
#include "director-request.h"

#define DIRECTOR_REQUEST_TIMEOUT_SECS 30
#define RING_NOCONN_WARNING_DELAY_MSECS (2*1000)

enum director_request_delay_reason {
	REQUEST_DELAY_NONE = 0,
	REQUEST_DELAY_RINGNOTHANDSHAKED,
	REQUEST_DELAY_RINGNOTSYNCED,
	REQUEST_DELAY_NOHOSTS,
	REQUEST_DELAY_WEAK,
	REQUEST_DELAY_KILL
};

static const char *delay_reason_strings[] = {
	"unknown",
	"ring not handshaked",
	"ring not synced",
	"no hosts",
	"weak user",
	"kill waiting"
};

struct director_request {
	struct director *dir;

	time_t create_time;
	unsigned int username_hash;
	enum director_request_delay_reason delay_reason;
	char *username_tag;

	director_request_callback *callback;
	void *context;
};

static void director_request_free(struct director_request *request)
{
	i_free(request->username_tag);
	i_free(request);
}

static const char *
director_request_get_timeout_error(struct director_request *request,
				   struct user *user, string_t *str)
{
	unsigned int secs;

	str_truncate(str, 0);
	str_printfa(str, "Timeout because %s - queued for %u secs (",
		    delay_reason_strings[request->delay_reason],
		    (unsigned int)(ioloop_time - request->create_time));

	if (request->dir->ring_last_sync_time == 0)
		str_append(str, "Ring has never been synced");
	else {
		secs = ioloop_time - request->dir->ring_last_sync_time;
		if (request->dir->ring_synced)
			str_printfa(str, "Ring synced for %u secs", secs);
		else
			str_printfa(str, "Ring not synced for %u secs", secs);
	}

	if (user != NULL) {
		if (user->weak)
			str_append(str, ", weak user");
		str_printfa(str, ", user refreshed %u secs ago",
			    (unsigned int)(ioloop_time - user->timestamp));
	}
	str_printfa(str, ", hash=%u", request->username_hash);
	if (request->username_tag != NULL)
		str_printfa(str, ", tag=%s", request->username_tag);
	str_append_c(str, ')');
	return str_c(str);
}

static void director_request_timeout(struct director *dir)
{
	struct director_request **requestp, *request;
	struct user *user;
	const char *errormsg;
	string_t *str = t_str_new(128);

	while (array_count(&dir->pending_requests) > 0) {
		requestp = array_first_modifiable(&dir->pending_requests);
		request = *requestp;

		if (request->create_time +
		    DIRECTOR_REQUEST_TIMEOUT_SECS > ioloop_time)
			break;

		const char *tag_name = request->username_tag == NULL ? "" :
			request->username_tag;
		struct mail_tag *tag = mail_tag_find(dir->mail_hosts, tag_name);
		user = tag == NULL ? NULL :
			user_directory_lookup(tag->users, request->username_hash);

		errormsg = director_request_get_timeout_error(request,
							      user, str);
		if (user != NULL &&
		    request->delay_reason == REQUEST_DELAY_WEAK) {
			/* weakness appears to have gotten stuck. this is a
			   bug, but try to fix it for future requests by
			   removing the weakness. */
			user->weak = FALSE;
		}

		i_assert(dir->requests_delayed_count > 0);
		dir->requests_delayed_count--;

		array_delete(&dir->pending_requests, 0, 1);
		T_BEGIN {
			request->callback(NULL, NULL, errormsg, request->context);
		} T_END;
		director_request_free(request);
	}

	if (array_count(&dir->pending_requests) == 0 && dir->to_request != NULL)
		timeout_remove(&dir->to_request);
}

void director_request(struct director *dir, const char *username,
		      const char *tag,
		      director_request_callback *callback, void *context)
{
	struct director_request *request;
	unsigned int username_hash;

	if (!director_get_username_hash(dir, username,
					&username_hash)) {
		callback(NULL, NULL, "Failed to expand director_username_hash", context);
		return;
	}

	dir->num_requests++;

	request = i_new(struct director_request, 1);
	request->dir = dir;
	request->create_time = ioloop_time;
	request->username_hash = username_hash;
	request->username_tag = tag[0] == '\0' ? NULL : i_strdup(tag);
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
	array_push_back(&dir->pending_requests, &request);
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

static bool
director_request_existing(struct director_request *request, struct user *user)
{
	struct director *dir = request->dir;
	struct mail_host *host;

	if (USER_IS_BEING_KILLED(user)) {
		/* delay processing this user's connections until
		   its existing connections have been killed */
		request->delay_reason = REQUEST_DELAY_KILL;
		dir_debug("request: %u waiting for kill to finish",
			  user->username_hash);
		return FALSE;
	}
	if (dir->right == NULL && dir->ring_synced) {
		/* looks like all the other directors have died. we can do
		   whatever we want without breaking anything. remove the
		   user's weakness just in case it was set to TRUE when we
		   had more directors. */
		user->weak = FALSE;
		return TRUE;
	}

	if (user->weak) {
		/* wait for user to become non-weak */
		request->delay_reason = REQUEST_DELAY_WEAK;
		dir_debug("request: %u waiting for weakness",
			  request->username_hash);
		return FALSE;
	}
	if (!user_directory_user_is_near_expiring(user->host->tag->users, user))
		return TRUE;

	/* user is close to being expired. another director may have
	   already expired it. */
	host = mail_host_get_by_hash(dir->mail_hosts, user->username_hash,
				     user->host->tag->name);
	if (!dir->ring_synced) {
		/* try again later once ring is synced */
		request->delay_reason = REQUEST_DELAY_RINGNOTSYNCED;
		dir_debug("request: %u waiting for sync for making weak",
			  request->username_hash);
		return FALSE;
	}
	if (user->host == host) {
		/* doesn't matter, other directors would
		   assign the user the same way regardless */
		dir_debug("request: %u would be weak, but host doesn't change", request->username_hash);
		return TRUE;
	}

	/* We have to worry about two separate timepoints in here:

	   a) some directors think the user isn't expiring, and
	   others think the user is near expiring

	   b) some directors think the user is near expiring, and
	   others think the user has already expired

	   What we don't have to worry about is:

	   !c) some directors think the user isn't expiring, and
	   others think the user has already expired

	   If !c) happens, the user might get redirected to different backends.
	   We'll use a large enough timeout between a) and b) states, so that
	   !c) should never happen.

	   So what we'll do here is:

	   1. Send a USER-WEAK notification to all directors with the new host.
	   2. Each director receiving USER-WEAK refreshes the user's timestamp
	   and host, but marks the user as being weak.
	   3. Once USER-WEAK has reached all directors, a real USER update is
	   sent, which removes the weak-flag.
	   4. If a director ever receives a USER update for a weak user, the
	   USER update overrides the host and removes the weak-flag.
	   5. Director doesn't let any weak user log in, until the weak-flag
	   gets removed.
	*/
	if (dir->ring_min_version < DIRECTOR_VERSION_WEAK_USERS) {
		/* weak users not supported by ring currently */
		return TRUE;
	} else {
		user->weak = TRUE;
		director_update_user_weak(dir, dir->self_host, NULL, NULL, user);
		request->delay_reason = REQUEST_DELAY_WEAK;
		dir_debug("request: %u set to weak", request->username_hash);
		return FALSE;
	}
}

static bool director_request_continue_real(struct director_request *request)
{
	struct director *dir = request->dir;
	struct mail_host *host;
	struct user *user;
	const char *tag;
	struct mail_tag *mail_tag;

	if (!dir->ring_handshaked) {
		/* delay requests until ring handshaking is complete */
		dir_debug("request: %u waiting for handshake",
			  request->username_hash);
		ring_log_delayed_warning(dir);
		request->delay_reason = REQUEST_DELAY_RINGNOTHANDSHAKED;
		return FALSE;
	}

	tag = request->username_tag == NULL ? "" : request->username_tag;
	mail_tag = mail_tag_find(dir->mail_hosts, tag);
	user = mail_tag == NULL ? NULL :
		user_directory_lookup(mail_tag->users, request->username_hash);

	if (user != NULL) {
		i_assert(user->host->tag == mail_tag);
		if (!director_request_existing(request, user))
			return FALSE;
		user_directory_refresh(mail_tag->users, user);
		dir_debug("request: %u refreshed timeout to %u",
			  request->username_hash, user->timestamp);
	} else {
		if (!dir->ring_synced) {
			/* delay adding new users until ring is again synced */
			ring_log_delayed_warning(dir);
			request->delay_reason = REQUEST_DELAY_RINGNOTSYNCED;
			dir_debug("request: %u waiting for sync for adding",
				  request->username_hash);
			return FALSE;
		}
		host = mail_host_get_by_hash(dir->mail_hosts,
					     request->username_hash, tag);
		if (host == NULL) {
			/* all hosts have been removed */
			request->delay_reason = REQUEST_DELAY_NOHOSTS;
			dir_debug("request: %u waiting for hosts",
				  request->username_hash);
			return FALSE;
		}
		user = user_directory_add(host->tag->users,
					  request->username_hash,
					  host, ioloop_time);
		dir_debug("request: %u added timeout to %u (hosts_hash=%u)",
			  request->username_hash, user->timestamp,
			  mail_hosts_hash(dir->mail_hosts));
	}

	i_assert(!user->weak);
	director_update_user(dir, dir->self_host, user);
	T_BEGIN {
		request->callback(user->host, user->host->hostname,
				  NULL, request->context);
	} T_END;
	director_request_free(request);
	return TRUE;
}

bool director_request_continue(struct director_request *request)
{
	if (request->delay_reason != REQUEST_DELAY_NONE) {
		i_assert(request->dir->requests_delayed_count > 0);
		request->dir->requests_delayed_count--;
	}
	if (!director_request_continue_real(request)) {
		i_assert(request->delay_reason != REQUEST_DELAY_NONE);
		request->dir->requests_delayed_count++;
		return FALSE;
	}
	return TRUE;
}
