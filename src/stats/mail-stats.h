#ifndef MAIL_STATS_H
#define MAIL_STATS_H

#include <sys/time.h>

#include "net.h"
#include "guid.h"
#include "stats.h"

struct stats_send_ctx;

struct mail_command {
	struct mail_command *stable_prev, *stable_next;
	struct mail_command *session_prev, *session_next;

	struct mail_session *session;
	char *name, *args;
	/* non-zero id means the command is still running */
	unsigned int id;

	struct timeval last_update;
	struct stats *stats;

	int refcount;
};

struct mail_session {
	struct mail_session *stable_prev, *stable_next;
	struct mail_session *sorted_prev, *sorted_next;
	struct mail_session *user_prev, *user_next;
	struct mail_session *ip_prev, *ip_next;

	/* if id="", the session no longer exists */
	char *id;
	struct mail_user *user;
	const char *service;
	pid_t pid;
	/* ip address may be NULL if there's none */
	struct mail_ip *ip;
	struct timeout *to_idle;

	struct stats *stats;
	struct timeval last_update;
	unsigned int num_cmds;

	bool disconnected;
	unsigned int highest_cmd_id;
	int refcount;
	struct mail_command *commands;
};

struct mail_user {
	struct mail_user *stable_prev, *stable_next;
	struct mail_user *sorted_prev, *sorted_next;
	struct mail_user *domain_prev, *domain_next;
	char *name;
	struct mail_domain *domain;
	time_t reset_timestamp;

	struct timeval last_update;
	struct stats *stats;
	unsigned int num_logins;
	unsigned int num_cmds;

	int refcount;
	struct mail_session *sessions;
};

struct mail_domain {
	struct mail_domain *stable_prev, *stable_next;
	struct mail_domain *sorted_prev, *sorted_next;
	char *name;
	time_t reset_timestamp;

	struct timeval last_update;
	struct stats *stats;
	unsigned int num_logins;
	unsigned int num_cmds;
	unsigned int num_connected_sessions;

	int refcount;
	struct mail_user *users;
};

struct mail_ip {
	struct mail_ip *stable_prev, *stable_next;
	struct mail_ip *sorted_prev, *sorted_next;
	struct ip_addr ip;
	time_t reset_timestamp;

	struct timeval last_update;
	struct stats *stats;
	unsigned int num_logins;
	unsigned int num_cmds;
	unsigned int num_connected_sessions;

	int refcount;
	struct mail_session *sessions;
};

struct mail_global {
	time_t reset_timestamp;

	struct timeval last_update;
	struct stats *stats;
	unsigned int num_logins;
	unsigned int num_cmds;
	unsigned int num_connected_sessions;

	struct timeout *to_stats_send;
	struct stats_send_ctx *stats_send_ctx;
};

extern struct mail_global mail_global_stats;

void mail_global_init(void);
void mail_global_deinit(void);

void mail_global_login(void);
void mail_global_disconnected(void);
void mail_global_refresh(const struct stats *diff_stats);

#endif
