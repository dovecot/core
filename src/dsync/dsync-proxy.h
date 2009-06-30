#ifndef DSYNC_PROXY_H
#define DSYNC_PROXY_H

#include "dsync-data.h"

struct dsync_message;
struct dsync_mailbox;

void dsync_proxy_msg_export(string_t *str, const struct dsync_message *msg);
int dsync_proxy_msg_parse_flags(pool_t pool, const char *str,
				struct dsync_message *msg_r);
int dsync_proxy_msg_import_unescaped(pool_t pool, struct dsync_message *msg_r,
				     const char *const *args,
				     const char **error_r);
int dsync_proxy_msg_import(pool_t pool, const char *str,
			   struct dsync_message *msg_r, const char **error_r);

void dsync_proxy_mailbox_export(string_t *str, const struct dsync_mailbox *box);
int dsync_proxy_mailbox_import(pool_t pool, const char *str,
			       struct dsync_mailbox *box_r,
			       const char **error_r);

void dsync_proxy_mailbox_guid_export(string_t *str,
				     const mailbox_guid_t *mailbox);
int dsync_proxy_mailbox_guid_import(const char *str, mailbox_guid_t *guid_r);

#endif
