#ifndef POP3_CLIENT_H
#define POP3_CLIENT_H

struct client;
struct mail_storage;

typedef void command_func_t(struct client *client);

#define MSGS_BITMASK_SIZE(client) \
	(((client)->messages_count + (CHAR_BIT-1)) / CHAR_BIT)

/*
   pop3_msn = 1..n in the POP3 protocol
   msgnum = 0..n-1 = pop3_msn-1
   seq = 1..n = mail's sequence number in lib-storage. when pop3 sort ordering
     is used, msgnum_to_seq_map[] can be used for translation.
*/
struct client {
	struct client *prev, *next;

	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_idle, *to_commit;

	command_func_t *cmd;
	void *cmd_context;

	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	struct mail_namespace *inbox_ns;
	struct mailbox *mailbox;
	struct mailbox_transaction_context *trans;

	time_t last_input, last_output;
	unsigned int bad_counter;
	unsigned int highest_expunged_fetch_msgnum;

	unsigned int uid_validity;
	unsigned int messages_count;
	unsigned int deleted_count, expunged_count, seen_change_count;
	uoff_t total_size;
	uoff_t deleted_size;
	uint32_t last_seen_pop3_msn, lowest_retr_pop3_msn;

	/* [msgnum] contains mail seq. anything after it has seq = msgnum+1 */
	uint32_t *msgnum_to_seq_map;
	uint32_t msgnum_to_seq_map_count;

	uoff_t top_bytes;
	uoff_t retr_bytes;
	unsigned int top_count;
	unsigned int retr_count;

	/* [msgnum] */
	uint32_t *message_uidl_hashes;
	uoff_t *message_sizes;
	/* [msgnum/8] & msgnum%8 */
	unsigned char *deleted_bitmask;
	unsigned char *seen_bitmask;

	/* settings: */
	const struct pop3_settings *set;
	const struct mail_storage_settings *mail_set;
	enum uidl_keys uidl_keymask;

	unsigned int disconnected:1;
	unsigned int deleted:1;
	unsigned int waiting_input:1;
	unsigned int anvil_sent:1;
	unsigned int message_uidl_hashes_save:1;
};

extern struct client *pop3_clients;
extern unsigned int pop3_client_count;

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out, struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct pop3_settings *set);
void client_destroy(struct client *client, const char *reason);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);

/* Send a line of data to client */
int client_send_line(struct client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void client_send_storage_error(struct client *client);

bool client_handle_input(struct client *client);
bool client_update_mails(struct client *client);

void clients_destroy_all(void);

#endif
