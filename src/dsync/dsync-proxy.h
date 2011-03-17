#ifndef DSYNC_PROXY_H
#define DSYNC_PROXY_H

#include "dsync-data.h"

#define DSYNC_PROXY_CLIENT_TIMEOUT_MSECS (14*60*1000)
#define DSYNC_PROXY_SERVER_TIMEOUT_MSECS (15*60*1000)

#define DSYNC_PROXY_CLIENT_GREETING_LINE "dsync-client\t1"
#define DSYNC_PROXY_SERVER_GREETING_LINE "dsync-server\t1"

struct dsync_message;
struct dsync_mailbox;

void dsync_proxy_strings_export(string_t *str,
				const ARRAY_TYPE(const_string) *strings);

void dsync_proxy_msg_export(string_t *str, const struct dsync_message *msg);
int dsync_proxy_msg_parse_flags(pool_t pool, const char *str,
				struct dsync_message *msg_r);
int dsync_proxy_msg_import_unescaped(pool_t pool, const char *const *args,
				     struct dsync_message *msg_r,
				     const char **error_r);
int dsync_proxy_msg_import(pool_t pool, const char *str,
			   struct dsync_message *msg_r, const char **error_r);

void dsync_proxy_msg_static_export(string_t *str,
				   const struct dsync_msg_static_data *msg);
int dsync_proxy_msg_static_import(pool_t pool, const char *str,
				  struct dsync_msg_static_data *msg_r,
				  const char **error_r);
int dsync_proxy_msg_static_import_unescaped(pool_t pool,
					    const char *const *args,
					    struct dsync_msg_static_data *msg_r,
					    const char **error_r);

void dsync_proxy_mailbox_export(string_t *str, const struct dsync_mailbox *box);
int dsync_proxy_mailbox_import(pool_t pool, const char *str,
			       struct dsync_mailbox *box_r,
			       const char **error_r);
int dsync_proxy_mailbox_import_unescaped(pool_t pool, const char *const *args,
					 struct dsync_mailbox *box_r,
					 const char **error_r);

void dsync_proxy_mailbox_guid_export(string_t *str,
				     const mailbox_guid_t *mailbox);
int dsync_proxy_mailbox_guid_import(const char *str, mailbox_guid_t *guid_r);

void dsync_proxy_send_dot_output(struct ostream *output, bool *last_lf,
				 const unsigned char *data, size_t size);

#endif
