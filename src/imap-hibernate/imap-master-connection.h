#ifndef IMAP_MASTER_CONNECTION_H
#define IMAP_MASTER_CONNECTION_H

struct imap_master_connection;

typedef void
imap_master_connection_send_callback_t(void *context, struct ostream *output);
typedef void
imap_master_connection_read_callback_t(void *context, const char *reply);

/* Returns 1 = success, 0 = retry later, -1 = error */
int imap_master_connection_init(const char *path,
				imap_master_connection_send_callback_t *send_callback,
				imap_master_connection_read_callback_t *read_callback,
				void *context,
				struct imap_master_connection **conn_r,
				const char **error_r);
void imap_master_connection_deinit(struct imap_master_connection **conn);
void imap_master_connection_free(struct imap_master_connection **conn);

void imap_master_connections_init(void);
void imap_master_connections_deinit(void);

#endif
