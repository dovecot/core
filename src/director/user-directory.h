#ifndef USER_DIRECTORY_H
#define USER_DIRECTORY_H

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
	/* Wait for a while for the user connections to actually die */
	USER_KILL_STATE_DELAY
};

struct user {
	/* sorted by time */
	struct user *prev, *next;

	/* first 32 bits of MD5(username). collisions are quite unlikely, but
	   even if they happen it doesn't matter - the users are just
	   redirected to same server */
	unsigned int username_hash;
	unsigned int timestamp;

	struct mail_host *host;

	/* Move timeout to make sure user's connections won't silently hang
	   indefinitely if there is some trouble moving it. */
	struct timeout *to_move;
	/* If not USER_KILL_STATE_NONE, don't allow new connections until all
	   directors have killed the user's connections. */
	enum user_kill_state kill_state;
};

/* Create a new directory. Users are dropped if their time gets older
   than timeout_secs. */
struct user_directory *user_directory_init(unsigned int timeout_secs);
void user_directory_deinit(struct user_directory **dir);

/* Look up username from directory. Returns NULL if not found. */
struct user *user_directory_lookup(struct user_directory *dir,
				   unsigned int username_hash);
/* Add a user to directory and return it. */
struct user *
user_directory_add(struct user_directory *dir, unsigned int username_hash,
		   struct mail_host *host, time_t timestamp);
/* Refresh user's timestamp */
void user_directory_refresh(struct user_directory *dir, struct user *user);

/* Remove all users that have pointers to given host */
void user_directory_remove_host(struct user_directory *dir,
				struct mail_host *host);

unsigned int user_directory_get_username_hash(const char *username);

/* Returns TRUE if user still potentially has connections. */
bool user_directory_user_has_connections(struct user_directory *dir,
					 struct user *user);

struct user_directory_iter *
user_directory_iter_init(struct user_directory *dir);
struct user *user_directory_iter_next(struct user_directory_iter *iter);
void user_directory_iter_deinit(struct user_directory_iter **iter);

#endif
