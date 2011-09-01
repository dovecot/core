/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-user.h"
#include "mail-ip.h"
#include "mail-session.h"

/* If session doesn't receive any updates for this long, assume that the
   process associated with it has crashed, and forcibly disconnect the
   session. Must be larger than SESSION_STATS_FORCE_REFRESH_SECS in
   stats plugin */
#define MAIL_SESSION_IDLE_TIMEOUT_MSECS (1000*60*10)

static struct hash_table *mail_sessions_hash;
/* sessions are sorted by their last_update timestamp, oldest first */
static struct mail_session *mail_sessions_head, *mail_sessions_tail;
struct mail_session *stable_mail_sessions;

static size_t mail_session_memsize(const struct mail_session *session)
{
	return sizeof(*session) + strlen(session->service) + 1;
}

static void mail_session_disconnect(struct mail_session *session)
{
	hash_table_remove(mail_sessions_hash, session->guid);
	session->disconnected = TRUE;
	timeout_remove(&session->to_idle);
	mail_session_unref(&session);
}

static void mail_session_idle_timeout(struct mail_session *session)
{
	i_warning("Session %s appears to be have crashed, disconnecting it",
		  guid_128_to_string(session->guid));
	mail_session_disconnect(session);
}

int mail_session_connect_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	guid_128_t session_guid;
	struct ip_addr ip;
	unsigned int i;

	/* <session guid> <username> <service> [key=value ..] */
	if (str_array_length(args) < 3) {
		*error_r = "CONNECT: Too few parameters";
		return -1;
	}
	if (guid_128_from_string(args[0], session_guid) < 0) {
		*error_r = "CONNECT: Invalid GUID";
		return -1;
	}
	session = hash_table_lookup(mail_sessions_hash, session_guid);
	if (session != NULL) {
		*error_r = "CONNECT: Duplicate session GUID";
		return -1;
	}
	session = i_new(struct mail_session, 1);
	session->refcount = 1; /* unrefed at disconnect */
	session->service = i_strdup(args[2]);
	memcpy(session->guid, session_guid, sizeof(session->guid));
	session->last_update = ioloop_timeval;
	session->to_idle = timeout_add(MAIL_SESSION_IDLE_TIMEOUT_MSECS,
				       mail_session_idle_timeout, session);

	session->user = mail_user_login(args[1]);
	for (i = 3; args[i] != NULL; i++) {
		if (strncmp(args[i], "rip=", 4) == 0 &&
		    net_addr2ip(args[i] + 4, &ip) == 0)
			session->ip = mail_ip_login(&ip);
	}

	hash_table_insert(mail_sessions_hash, session->guid, session);
	DLLIST_PREPEND_FULL(&stable_mail_sessions, session,
			    stable_prev, stable_next);
	DLLIST2_APPEND_FULL(&mail_sessions_head, &mail_sessions_tail, session,
			    sorted_prev, sorted_next);
	DLLIST_PREPEND_FULL(&session->user->sessions, session,
			    user_prev, user_next);
	mail_user_ref(session->user);
	if (session->ip != NULL) {
		DLLIST_PREPEND_FULL(&session->ip->sessions, session,
				    ip_prev, ip_next);
		mail_ip_ref(session->ip);
	}
	global_memory_alloc(mail_session_memsize(session));
	return 0;
}

void mail_session_ref(struct mail_session *session)
{
	session->refcount++;
}

void mail_session_unref(struct mail_session **_session)
{
	struct mail_session *session = *_session;

	i_assert(session->refcount > 0);
	session->refcount--;

	*_session = NULL;
}

static void mail_session_free(struct mail_session *session)
{
	i_assert(session->refcount == 0);

	global_memory_free(mail_session_memsize(session));

	if (session->to_idle != NULL)
		timeout_remove(&session->to_idle);
	if (!session->disconnected)
		hash_table_remove(mail_sessions_hash, session->guid);
	DLLIST_REMOVE_FULL(&stable_mail_sessions, session,
			   stable_prev, stable_next);
	DLLIST2_REMOVE_FULL(&mail_sessions_head, &mail_sessions_tail, session,
			    sorted_prev, sorted_next);
	DLLIST_REMOVE_FULL(&session->user->sessions, session,
			   user_prev, user_next);
	mail_user_unref(&session->user);
	if (session->ip != NULL) {
		DLLIST_REMOVE_FULL(&session->ip->sessions, session,
				   ip_prev, ip_next);
		mail_ip_unref(&session->ip);
	}

	i_free(session->service);
	i_free(session);
}

int mail_session_lookup(const char *guid, struct mail_session **session_r,
			const char **error_r)
{
	guid_128_t session_guid;

	if (guid == NULL) {
		*error_r = "Too few parameters";
		return -1;
	}
	if (guid_128_from_string(guid, session_guid) < 0) {
		*error_r = "Invalid GUID";
		return -1;
	}
	*session_r = hash_table_lookup(mail_sessions_hash, session_guid);
	if (*session_r == NULL) {
		i_warning("mail disconnect couldn't find session GUID: %s",
			  guid_128_to_string(session_guid));
		return 0;
	}
	return 1;
}

int mail_session_disconnect_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	int ret;

	/* <session guid> */
	if ((ret = mail_session_lookup(args[0], &session, error_r)) <= 0)
		return ret;

	mail_session_disconnect(session);
	return 0;
}

void mail_session_refresh(struct mail_session *session,
			  const struct mail_stats *diff_stats)
{
	timeout_reset(session->to_idle);

	if (diff_stats != NULL)
		mail_stats_add(&session->stats, diff_stats);
	session->last_update = ioloop_timeval;
	DLLIST2_REMOVE_FULL(&mail_sessions_head, &mail_sessions_tail, session,
			    sorted_prev, sorted_next);
	DLLIST2_APPEND_FULL(&mail_sessions_head, &mail_sessions_tail, session,
			    sorted_prev, sorted_next);

	mail_user_refresh(session->user, diff_stats);
	if (session->ip != NULL)
		mail_ip_refresh(session->ip, diff_stats);
}

int mail_session_update_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	struct mail_stats stats, diff_stats;
	int ret;

	/* <session guid> [key=value ..] */
	if ((ret = mail_session_lookup(args[0], &session, error_r)) <= 0)
		return ret;

	if (mail_stats_parse(args+1, &stats, error_r) < 0) {
		*error_r = t_strconcat("UPDATE-SESSION: ", *error_r, NULL);
		return -1;
	}

	if (!mail_stats_diff(&session->stats, &stats, &diff_stats)) {
		*error_r = "UPDATE-SESSION: stats shrank";
		return -1;
	}
	mail_session_refresh(session, &diff_stats);
	return 0;
}

void mail_sessions_free_memory(void)
{
	while (mail_sessions_head != NULL &&
	       mail_sessions_head->refcount == 0) {
		i_assert(mail_sessions_head->disconnected);
		mail_session_free(mail_sessions_head);

		if (global_used_memory < stats_settings->memory_limit)
			break;
		if (ioloop_time -
		    mail_sessions_head->last_update.tv_sec < stats_settings->session_min_time)
			break;
	}
}

void mail_sessions_init(void)
{
	mail_sessions_hash =
		hash_table_create(default_pool, default_pool, 0,
				  guid_128_hash, guid_128_cmp);
}

void mail_sessions_deinit(void)
{
	while (mail_sessions_head != NULL)
		mail_session_free(mail_sessions_head);
	hash_table_destroy(&mail_sessions_hash);
}
