#ifndef DIRECTOR_H
#define DIRECTOR_H

#include "network.h"
#include "director-settings.h"

struct director;
struct mail_host;
struct user;

typedef void director_state_change_callback_t(struct director *dir);

struct director {
	const struct director_settings *set;

	/* IP and port of this director. self_host->ip/port must equal these. */
	struct ip_addr self_ip;
	unsigned int self_port;

	unsigned int test_port;

	struct director_host *self_host;
	struct director_connection *left, *right;
	/* all director connections */
	struct director_connection *connections;
	struct timeout *to_reconnect;

	/* current mail hosts */
	struct mail_host_list *mail_hosts;
	/* original mail hosts configured in config file.
	   this is used only for doveadm lookups */
	struct mail_host_list *orig_config_hosts;
	/* temporary user -> host associations */
	struct user_directory *users;

	/* these requests are waiting for directors to be in synced */
	ARRAY_DEFINE(pending_requests, struct director_request *);
	struct timeout *to_request;
	struct timeout *to_handshake_warning;

	director_state_change_callback_t *state_change_callback;

	/* director hosts are sorted by IP (and port) */
	ARRAY_DEFINE(dir_hosts, struct director_host *);

	struct ipc_client *ipc_proxy;
	unsigned int sync_seq;

	/* director ring handshaking is complete.
	   director can start serving clients. */
	unsigned int ring_handshaked:1;
	unsigned int ring_handshake_warning_sent:1;
	unsigned int ring_synced:1;
	unsigned int sync_frozen:1;
	unsigned int sync_pending:1;
	unsigned int debug:1;
};

/* Create a new director. If listen_ip specifies an actual IP, it's used with
   listen_port for finding ourself from the director_servers setting.
   listen_port is used regardless by director_host_add_from_string() for hosts
   without specified port. */
struct director *
director_init(const struct director_settings *set,
	      const struct ip_addr *listen_ip, unsigned int listen_port,
	      director_state_change_callback_t *callback);
void director_deinit(struct director **dir);

/* Start connecting to other directors */
void director_connect(struct director *dir);

void director_set_ring_handshaked(struct director *dir);
void director_set_ring_synced(struct director *dir);
void director_set_state_changed(struct director *dir);

void director_update_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host);
void director_remove_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host);
void director_flush_host(struct director *dir, struct director_host *src,
			 struct director_host *orig_src,
			 struct mail_host *host);
void director_update_user(struct director *dir, struct director_host *src,
			  struct user *user);
void director_move_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src,
			unsigned int username_hash, struct mail_host *host);
void director_user_killed(struct director *dir, unsigned int username_hash);
void director_user_killed_everywhere(struct director *dir,
				     struct director_host *src,
				     struct director_host *orig_src,
				     unsigned int username_hash);

void director_sync_freeze(struct director *dir);
void director_sync_thaw(struct director *dir);

/* Send data to all directors using both left and right connections
   (unless they're the same). */
void director_update_send(struct director *dir, struct director_host *src,
			  const char *data);

int director_connect_host(struct director *dir, struct director_host *host);

#endif
