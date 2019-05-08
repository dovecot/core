#ifndef POP3_CLIENT_H
#define POP3_CLIENT_H

#include "seq-range-array.h"

struct client;
struct mail_storage;
struct mail_storage_service_ctx;

typedef void command_func_t(struct client *client);

#define MSGS_BITMASK_SIZE(client) \
	(MALLOC_ADD((client)->messages_count, (CHAR_BIT-1)) / CHAR_BIT)

/* Stop reading input when output buffer has this many bytes. Once the buffer
   size has dropped to half of it, start reading input again. */
#define POP3_OUTBUF_THROTTLE_SIZE 4096

#define POP3_CLIENT_OUTPUT_FULL(client) \
	(o_stream_get_buffer_used_size((client)->output) >= POP3_OUTBUF_THROTTLE_SIZE)

struct pop3_client_vfuncs {
	void (*destroy)(struct client *client, const char *reason);

};

/*
   pop3_msn = 1..n in the POP3 protocol
   msgnum = 0..n-1 = pop3_msn-1
   seq = 1..n = mail's sequence number in lib-storage. when pop3 sort ordering
     is used, msgnum_to_seq_map[] can be used for translation.
*/
struct client {
	struct client *prev, *next;

	struct pop3_client_vfuncs v;

	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_idle, *to_commit;

	command_func_t *cmd;
	void *cmd_context;

	pool_t pool;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	struct mail_namespace *inbox_ns;
	struct mailbox *mailbox;
	struct mailbox_transaction_context *trans;
	struct mail_keywords *deleted_kw;

	struct timeout *to_session_dotlock_refresh;
	struct dotlock *session_dotlock;

	time_t last_input, last_output;
	unsigned int bad_counter;
	unsigned int highest_expunged_fetch_msgnum;

	unsigned int uid_validity;
	unsigned int messages_count;
	unsigned int deleted_count, seen_change_count;
	uoff_t total_size;
	uoff_t deleted_size;
	uint32_t last_seen_pop3_msn, lowest_retr_pop3_msn;

	/* All sequences currently visible in the mailbox. */
	ARRAY_TYPE(seq_range) all_seqs;
	uint32_t highest_seq;

	/* [msgnum] contains mail seq. anything after it has seq = msgnum+1 */
	uint32_t *msgnum_to_seq_map;
	uint32_t msgnum_to_seq_map_count;

	uoff_t top_bytes;
	uoff_t retr_bytes;
	unsigned int top_count;
	unsigned int retr_count;

	/* [msgnum] */
	const char **message_uidls;
	uoff_t *message_sizes;
	/* [msgnum/8] & msgnum%8 */
	unsigned char *deleted_bitmask;
	unsigned char *seen_bitmask;

	/* settings: */
	const struct pop3_settings *set;
	const struct mail_storage_settings *mail_set;
	pool_t uidl_pool;
	enum uidl_keys uidl_keymask;

	/* Module-specific contexts. */
	ARRAY(union pop3_module_context *) module_contexts;

	bool destroyed:1;
	bool disconnected:1;
	bool deleted:1;
	bool waiting_input:1;
	bool anvil_sent:1;
	bool message_uidls_save:1;
	bool delete_success:1;
	bool quit_seen:1;
};

struct pop3_module_register {
	unsigned int id;
};

union pop3_module_context {
	struct pop3_client_vfuncs super;
	struct pop3_module_register *reg;
};
extern struct pop3_module_register pop3_module_register;

extern struct client *pop3_clients;
extern unsigned int pop3_client_count;

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out,
			     struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct pop3_settings *set);
int client_init_mailbox(struct client *client, const char **error_r);
void client_destroy(struct client *client, const char *reason) ATTR_NULL(2);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);

/* Send a line of data to client */
void client_send_line(struct client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void client_send_storage_error(struct client *client);

bool client_handle_input(struct client *client);
bool client_update_mails(struct client *client);

void clients_destroy_all(void);

int pop3_lock_session(struct client *client);

#endif
