#ifndef IMAP_CLIENT_H
#define IMAP_CLIENT_H

#include "net.h"

struct imap_client_state {
	/* required: */
	const char *username, *mail_log_prefix;
	/* optional: */
	const char *session_id, *mailbox_vname, *userdb_fields, *stats;
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;
	time_t session_created;

	uid_t uid;
	gid_t gid;

	dev_t peer_dev;
	ino_t peer_ino;

	char *tag;
	const unsigned char *state;
	size_t state_size;

	guid_128_t anvil_conn_guid;
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

unsigned int imap_clients_kick(const char *user, const guid_128_t conn_guid);

void imap_clients_init(void);
void imap_clients_deinit(void);

#endif
