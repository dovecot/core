#ifndef DIRECTOR_H
#define DIRECTOR_H

#include "net.h"
#include "director-settings.h"

#define DIRECTOR_VERSION_NAME "director"
#define DIRECTOR_VERSION_MAJOR 1
#define DIRECTOR_VERSION_MINOR 9

/* weak users supported in protocol */
#define DIRECTOR_VERSION_WEAK_USERS 1
/* director ring remove supported */
#define DIRECTOR_VERSION_RING_REMOVE 2
/* quit reason supported */
#define DIRECTOR_VERSION_QUIT 3
/* user-kick supported */
#define DIRECTOR_VERSION_USER_KICK 4
/* options supported in handshake */
#define DIRECTOR_VERSION_OPTIONS 5
/* user tags supported */
#define DIRECTOR_VERSION_TAGS 5
/* up/down state is tracked */
#define DIRECTOR_VERSION_UPDOWN 6
/* user tag version 2 supported */
#define DIRECTOR_VERSION_TAGS_V2 7
/* user-kick-alt supported */
#define DIRECTOR_VERSION_USER_KICK_ALT 8
/* Users are sent as "U" command in handshake */
#define DIRECTOR_VERSION_HANDSHAKE_U_CMD 9
/* USER event with timestamp supported */
#define DIRECTOR_VERSION_USER_TIMESTAMP 9

/* Minimum time between even attempting to communicate with a director that
   failed due to a protocol error. */
#define DIRECTOR_PROTOCOL_FAILURE_RETRY_SECS 60

struct director;
struct mail_host;
struct user;
struct director_user_init;

enum user_kill_state {
	/* User isn't being killed */
	USER_KILL_STATE_NONE,
	/* We're still killing the user's connections */
	USER_KILL_STATE_KILLING,
	/* Like above, but our left side already announced it was finished
	   with killing its user connections */
	USER_KILL_STATE_KILLING_NOTIFY_RECEIVED,
	/* We're done killing, but we have to wait for the left side to
	   finish killing its user connections before sending USER-KILLED to
	   our right side */
	USER_KILL_STATE_KILLED_WAITING_FOR_NOTIFY,
	/* We're done killing, but waiting for USER-KILLED-EVERYWHERE
	   notification until this state gets reset. */
	USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE,
	/* Waiting for the flush socket to finish. */
	USER_KILL_STATE_FLUSHING,
	/* Wait for a while for the user connections to actually die. Note that
	   only at this stage we can be sure that all the directors know about
	   the user move (although it could be earlier if we added a new
	   USER-MOVED notification). */
	USER_KILL_STATE_DELAY
	/* NOTE: remember to update also user_kill_state_names[] */
};
extern const char *user_kill_state_names[USER_KILL_STATE_DELAY+1];

typedef void director_state_change_callback_t(struct director *dir);
typedef director_state_change_callback_t director_kick_callback_t;

/* When a user gets freed, the kill_ctx may still be left alive. It's also
   possible for the user to come back, in which case the kill_ctx is usually
   NULL, but another kill could have also started. The previous kill_ctx is
   valid only if it matches the current user's kill_ctx. */
#define DIRECTOR_KILL_CONTEXT_IS_VALID(user, ctx) \
	((user) != NULL && (user)->kill_ctx == ctx)

struct director_kill_context {
	struct director *dir;
	struct mail_tag *tag;
	unsigned int username_hash;
	struct ip_addr old_host_ip;
	unsigned int old_host_vhost_count;
	bool old_host_down;
	bool kill_is_self_initiated;
	bool callback_pending;

	enum user_kill_state kill_state;
	/* Move timeout to make sure user's connections won't silently hang
	   indefinitely if there is some trouble moving it. */
	struct timeout *to_move;
	/* IPC command to kick the user */
	struct ipc_client_cmd *ipc_cmd;

	/* these are set only for director_flush_socket handling: */
	struct ip_addr host_ip;
	struct program_client *pclient;
	struct ostream *reply;
	char *socket_path;
};

struct director {
	const struct director_settings *set;

	/* IP and port of this director. self_host->ip/port must equal these. */
	struct ip_addr self_ip;
	in_port_t self_port;

	in_port_t test_port;

	struct director_host *self_host;
	/* left and right connections are set only after they have finished
	   handshaking. until then they're in the connections list, although
	   updates are still sent to them during handshaking if the USER list
	   is long. */
	struct director_connection *left, *right;
	/* all director connections */
	ARRAY(struct director_connection *) connections;
	struct timeout *to_reconnect;
	struct timeout *to_sync;
	struct timeout *to_callback;

	/* current mail hosts */
	struct mail_host_list *mail_hosts;
	/* original mail hosts configured in config file.
	   this is used only for doveadm lookups */
	struct mail_host_list *orig_config_hosts;
	/* Number of users currently being moved */
	unsigned int users_moving_count;
	/* Number of users currently being kicked */
	unsigned int users_kicking_count;
	/* Number of requests currently delayed */
	unsigned int requests_delayed_count;

	/* these requests are waiting for directors to be in synced */
	ARRAY(struct director_request *) pending_requests;
	struct timeout *to_request;
	struct timeout *to_handshake_warning;

	director_state_change_callback_t *state_change_callback;
	director_kick_callback_t *kick_callback;

	/* director hosts are sorted by IP (and port) */
	ARRAY(struct director_host *) dir_hosts;
	struct timeout *to_remove_dirs;

	struct ipc_client *ipc_proxy;
	unsigned int sync_seq;
	unsigned int ring_change_counter;
	unsigned int last_sync_sent_ring_change_counter;
	/* Timestamp when the last SYNC was initiated by us */
	struct timeval last_sync_start_time;
	/* the lowest minor version supported by the ring */
	unsigned int ring_min_version;
	/* Timestamp when ring became synced or unsynced the last time */
	time_t ring_last_sync_time;
	/* How many milliseconds it took for the last SYNC to travel through
	   the ring. */
	unsigned int last_sync_msecs;

	time_t ring_first_alone;

	uint64_t num_requests, num_incoming_requests;
	uint64_t ring_traffic_input, ring_traffic_output;

	/* director ring handshaking is complete.
	   director can start serving clients. */
	bool ring_handshaked:1;
	bool ring_handshake_warning_sent:1;
	bool ring_synced:1;
	bool sync_frozen:1;
	bool sync_pending:1;
};

extern bool director_debug;

/* Create a new director. If listen_ip specifies an actual IP, it's used with
   listen_port for finding ourself from the director_servers setting.
   listen_port is used regardless by director_host_add_from_string() for hosts
   without specified port. */
struct director *
director_init(const struct director_settings *set,
	      const struct ip_addr *listen_ip, in_port_t listen_port,
	      director_state_change_callback_t *callback,
	      director_kick_callback_t *kick_callback);
void director_deinit(struct director **dir);
void director_find_self(struct director *dir);

/* Start connecting to other directors */
void director_connect(struct director *dir, const char *reason);

void director_set_ring_handshaked(struct director *dir);
void director_set_ring_synced(struct director *dir);
void director_set_ring_unsynced(struct director *dir);
void director_set_state_changed(struct director *dir);
void director_sync_send(struct director *dir, struct director_host *host,
			uint32_t seq, unsigned int minor_version,
			unsigned int timestamp, unsigned int hosts_hash);
bool director_resend_sync(struct director *dir);

void director_notify_ring_added(struct director_host *added_host,
				struct director_host *src, bool log);
void director_ring_remove(struct director_host *removed_host,
			  struct director_host *src);

void director_update_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host) ATTR_NULL(3);
void director_resend_hosts(struct director *dir);
void director_remove_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host) ATTR_NULL(2, 3);
void director_flush_host(struct director *dir, struct director_host *src,
			 struct director_host *orig_src,
			 struct mail_host *host) ATTR_NULL(3);
void director_update_user(struct director *dir, struct director_host *src,
			  struct user *user);
void director_update_user_weak(struct director *dir, struct director_host *src,
			       struct director_connection *src_conn,
			       struct director_host *orig_src,
			       struct user *user) ATTR_NULL(3);
void director_kill_user(struct director *dir, struct director_host *src,
			struct user *user, struct mail_tag *tag,
			struct mail_host *old_host, bool forced_kick);
void director_move_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src,
			unsigned int username_hash, struct mail_host *host)
	ATTR_NULL(3);
void director_kick_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src, const char *username)
	ATTR_NULL(3);
void director_kick_user_alt(struct director *dir, struct director_host *src,
			    struct director_host *orig_src,
			    const char *field, const char *value)
	ATTR_NULL(3);
void director_kick_user_hash(struct director *dir, struct director_host *src,
			     struct director_host *orig_src,
			     unsigned int username_hash,
			     const struct ip_addr *except_ip)
	ATTR_NULL(3);
void director_user_killed(struct director *dir, unsigned int username_hash);
void director_user_killed_everywhere(struct director *dir,
				     struct director_host *src,
				     struct director_host *orig_src,
				     unsigned int username_hash) ATTR_NULL(3);
void director_user_weak(struct director *dir, struct user *user);

void director_sync_freeze(struct director *dir);
void director_sync_thaw(struct director *dir);

/* Send data to all directors using both left and right connections
   (unless they're the same). */
void director_update_send(struct director *dir, struct director_host *src,
			  const char *cmd);
void director_update_send_version(struct director *dir,
				  struct director_host *src,
				  unsigned int min_version, const char *cmd);

int director_connect_host(struct director *dir, struct director_host *host,
			  const char *reason);

bool
director_get_username_hash(struct director *dir, const char *username,
			   unsigned int *hash_r);

void directors_init(void);
void directors_deinit(void);

void dir_debug(const char *fmt, ...) ATTR_FORMAT(1, 2);

struct director_user_iter *
director_iterate_users_init(struct director *dir, bool iter_until_current_tail);
struct user *director_iterate_users_next(struct director_user_iter *iter);
void director_iterate_users_deinit(struct director_user_iter **_iter);

#endif
