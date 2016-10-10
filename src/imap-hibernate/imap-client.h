#ifndef IMAP_CLIENT_H
#define IMAP_CLIENT_H

#include "net.h"

struct imap_client_state {
	/* required: */
	const char *username, *mail_log_prefix;
	/* optional: */
	const char *session_id, *userdb_fields, *stats;
	struct ip_addr local_ip, remote_ip;
	time_t session_created;

	uid_t uid;
	gid_t gid;

	dev_t peer_dev;
	ino_t peer_ino;

	char *tag;
	const unsigned char *state;
	size_t state_size;

	unsigned int imap_idle_notify_interval;
	bool idle_cmd;
	bool have_notify_fd;
	bool anvil_sent;
};

struct imap_client *
imap_client_create(int fd, const struct imap_client_state *state);
void imap_client_add_notify_fd(struct imap_client *client, int fd);
void imap_client_create_finish(struct imap_client *client);
void imap_client_destroy(struct imap_client **_client, const char *reason);

void imap_clients_init(void);
void imap_clients_deinit(void);

#endif
