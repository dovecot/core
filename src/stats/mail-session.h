#ifndef MAIL_SESSION_H
#define MAIL_SESSION_H

struct mail_stats;
struct mail_session;

extern struct mail_session *stable_mail_sessions;

int mail_session_connect_parse(const char *const *args, const char **error_r);
int mail_session_disconnect_parse(const char *const *args, const char **error_r);
int mail_session_update_parse(const char *const *args, const char **error_r);
int mail_session_cmd_update_parse(const char *const *args, const char **error_r);

void mail_session_ref(struct mail_session *session);
void mail_session_unref(struct mail_session **session);

int mail_session_lookup(const char *guid, struct mail_session **session_r,
			const char **error_r);
int mail_session_get(const char *guid, struct mail_session **session_r,
		     const char **error_r);
void mail_session_refresh(struct mail_session *session,
			  const struct mail_stats *diff_stats) ATTR_NULL(2);

void mail_sessions_free_memory(void);
void mail_sessions_init(void);
void mail_sessions_deinit(void);

#endif
