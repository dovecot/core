/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "str-table.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-user.h"
#include "mail-ip.h"
#include "mail-session.h"
#include "mail-domain.h"

/* If session doesn't receive any updates for this long, assume that the
   process associated with it has crashed, and forcibly disconnect the
   session. Must be larger than SESSION_STATS_FORCE_REFRESH_SECS in
   stats plugin */
#define MAIL_SESSION_IDLE_TIMEOUT_MSECS (1000*60*15)
/* If stats process crashes/restarts, existing processes keep sending status
   updates to it, but this process doesn't know their session IDs. If these
   missing IDs are found within this many seconds of starting the stats process,
   don't log a warning about them. (On a larger installation this avoids
   flooding the error log with hundreds of warnings.) */
#define SESSION_ID_WARN_HIDE_SECS (60*5)

static HASH_TABLE(char *, struct mail_session *) mail_sessions_hash;
/* sessions are sorted by their last_update timestamp, oldest first */
static struct mail_session *mail_sessions_head, *mail_sessions_tail;
static time_t session_id_warn_hide_until;
static bool session_id_hide_warned = FALSE;
static struct str_table *services;

struct mail_session *stable_mail_sessions;

static size_t mail_session_memsize(const struct mail_session *session)
{
	return sizeof(*session) + strlen(session->id) + 1;
}

static void mail_session_disconnect(struct mail_session *session)
{
	i_assert(!session->disconnected);

	mail_user_disconnected(session->user);
	if (session->ip != NULL)
		mail_ip_disconnected(session->ip);

	hash_table_remove(mail_sessions_hash, session->id);
	session->disconnected = TRUE;
	timeout_remove(&session->to_idle);
	mail_session_unref(&session);
}

static void mail_session_idle_timeout(struct mail_session *session)
{
	/* user="" service="" pid=0 is used for incoming sessions that were
	   received after we detected a stats process crash/restart. there's
	   no point in logging anything about them, since they contain no
	   useful information. */
	if (session->user->name[0] == '\0' && session->service[0] != '\0' &&
	    session->pid == 0) {
		i_warning("Session %s (user %s, service %s) "
			  "appears to have crashed, disconnecting it",
			  session->id, session->user->name, session->service);
	}
	mail_session_disconnect(session);
}

int mail_session_connect_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	const char *session_id;
	pid_t pid;
	struct ip_addr ip;
	unsigned int i;

	/* <session id> <username> <service> <pid> [key=value ..] */
	if (str_array_length(args) < 4) {
		*error_r = "CONNECT: Too few parameters";
		return -1;
	}
	session_id = args[0];
	if (str_to_pid(args[3], &pid) < 0) {
		*error_r = t_strdup_printf("CONNECT: Invalid pid %s for session ID %s",
					   args[3], session_id);
		return -1;
	}

	session = hash_table_lookup(mail_sessions_hash, session_id);
	if (session != NULL) {
		*error_r = t_strdup_printf(
			"CONNECT: Duplicate session ID %s for user %s service %s (old PID %ld, new PID %ld)",
			session_id, args[1], args[2], (long)session->pid, (long)pid);
		return -1;
	}
	session = i_malloc(MALLOC_ADD(sizeof(struct mail_session), stats_alloc_size()));
	session->stats = (void *)(session + 1);
	session->refcount = 1; /* unrefed at disconnect */
	session->id = i_strdup(session_id);
	session->service = str_table_ref(services, args[2]);
	session->pid = pid;
	session->last_update = ioloop_timeval;
	session->to_idle = timeout_add(MAIL_SESSION_IDLE_TIMEOUT_MSECS,
				       mail_session_idle_timeout, session);

	session->user = mail_user_login(args[1]);
	session->user->num_logins++;
	mail_domain_login(session->user->domain);

	for (i = 3; args[i] != NULL; i++) {
		if (str_begins(args[i], "rip=") &&
		    net_addr2ip(args[i] + 4, &ip) == 0)
			session->ip = mail_ip_login(&ip);
	}

	hash_table_insert(mail_sessions_hash, session->id, session);
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

	mail_global_login();
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

	timeout_remove(&session->to_idle);
	if (!session->disconnected)
		hash_table_remove(mail_sessions_hash, session->id);
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

	str_table_unref(services, &session->service);
	i_free(session->id);
	i_free(session);
}

static void mail_session_id_lost(const char *session_id)
{
	if (ioloop_time < session_id_warn_hide_until) {
		if (session_id_hide_warned)
			return;
		session_id_hide_warned = TRUE;
		i_warning("stats process appears to have crashed/restarted, "
			  "hiding missing session ID warnings for %d seconds",
			  (int)(session_id_warn_hide_until - ioloop_time));
		return;
	}
	i_warning("Couldn't find session ID: %s", session_id);
}

int mail_session_lookup(const char *id, struct mail_session **session_r,
			const char **error_r)
{
	if (id == NULL) {
		*error_r = "Too few parameters";
		return -1;
	}
	*session_r = hash_table_lookup(mail_sessions_hash, id);
	if (*session_r == NULL) {
		mail_session_id_lost(id);
		return 0;
	}
	return 1;
}

int mail_session_get(const char *id, struct mail_session **session_r,
		     const char **error_r)
{
	const char *new_args[5];
	int ret;

	if ((ret = mail_session_lookup(id, session_r, error_r)) != 0)
		return ret;

	/* Create a new dummy session to avoid repeated warnings */
	new_args[0] = id;
	new_args[1] = ""; /* username */
	new_args[2] = ""; /* service */
	new_args[3] = "0"; /* pid */
	new_args[4] = NULL;
	if (mail_session_connect_parse(new_args, error_r) < 0)
		i_unreached();
	if (mail_session_lookup(id, session_r, error_r) != 1)
		i_unreached();
	return 0;
}

int mail_session_disconnect_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	int ret;

	/* <session id> */
	if ((ret = mail_session_lookup(args[0], &session, error_r)) <= 0)
		return ret;

	if (!session->disconnected)
		mail_session_disconnect(session);
	return 0;
}

void mail_session_refresh(struct mail_session *session,
			  const struct stats *diff_stats)
{
	timeout_reset(session->to_idle);

	if (diff_stats != NULL)
		stats_add(session->stats, diff_stats);
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
	struct stats *new_stats, *diff_stats;
	buffer_t *buf;
	const char *error;

	/* <session id> <stats> */
	if (mail_session_get(args[0], &session, error_r) < 0)
		return -1;

	buf = t_buffer_create(256);
	if (args[1] == NULL ||
	    base64_decode(args[1], strlen(args[1]), NULL, buf) < 0) {
		*error_r = t_strdup_printf("UPDATE-SESSION %s %s %s: Invalid base64 input",
					   session->user->name,
					   session->service, session->id);
		return -1;
	}

	new_stats = stats_alloc(pool_datastack_create());
	diff_stats = stats_alloc(pool_datastack_create());

	if (!stats_import(buf->data, buf->used, session->stats, new_stats, &error)) {
		*error_r = t_strdup_printf("UPDATE-SESSION %s %s %s: %s",
					   session->user->name,
					   session->service, session->id, error);
		return -1;
	}

	if (!stats_diff(session->stats, new_stats, diff_stats, &error)) {
		*error_r = t_strdup_printf("UPDATE-SESSION %s %s %s: stats shrank: %s",
					   session->user->name,
					   session->service, session->id, error);
		return -1;
	}
	mail_session_refresh(session, diff_stats);
	return 0;
}

void mail_sessions_free_memory(void)
{
	unsigned int diff;

	while (mail_sessions_head != NULL &&
	       mail_sessions_head->refcount == 0) {
		i_assert(mail_sessions_head->disconnected);
		mail_session_free(mail_sessions_head);

		if (global_used_memory < stats_settings->memory_limit ||
		    mail_sessions_head == NULL)
			break;

		diff = ioloop_time - mail_sessions_head->last_update.tv_sec;
		if (diff < stats_settings->session_min_time)
			break;
	}
}

void mail_sessions_init(void)
{
	session_id_warn_hide_until =
		ioloop_time + SESSION_ID_WARN_HIDE_SECS;
	hash_table_create(&mail_sessions_hash, default_pool, 0,
			  str_hash, strcmp);
	services = str_table_init();
}

void mail_sessions_deinit(void)
{
	while (mail_sessions_head != NULL) {
		struct mail_session *session = mail_sessions_head;

		if (!session->disconnected)
			mail_session_unref(&session);
		mail_session_free(mail_sessions_head);
	}
	hash_table_destroy(&mail_sessions_hash);
	str_table_deinit(&services);
}
