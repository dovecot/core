#ifndef __IMAP_FETCH_H
#define __IMAP_FETCH_H

struct imap_fetch_context;

/* Returns 1 = ok, 0 = client output buffer full, call again, -1 = error.
   mail = NULL for deinit. */
typedef int imap_fetch_handler_t(struct imap_fetch_context *ctx,
				 struct mail *mail, void *context);

struct imap_fetch_handler {
	const char *name;

	/* Returns FALSE if arg is invalid. */
	int (*init)(struct imap_fetch_context *ctx, const char *name,
		    struct imap_arg **args);
};

struct imap_fetch_context_handler {
	imap_fetch_handler_t *handler;
	void *context;
};

struct imap_fetch_context {
	struct client *client;
	struct mailbox *box;

	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;

	enum mail_fetch_field fetch_data;
	buffer_t *all_headers_buf;
        struct mailbox_header_lookup_ctx *all_headers_ctx;

	buffer_t *handlers;

	struct mail *cur_mail;
	unsigned int cur_handler;
	uoff_t cur_size, cur_offset;
	string_t *cur_str;
	struct istream *cur_input;
	int skip_cr;
	int (*cont_handler)(struct imap_fetch_context *ctx);

	unsigned int select_counter;

	struct mail_full_flags seen_flag;

	unsigned int flags_have_handler:1;
	unsigned int flags_update_seen:1;
	unsigned int flags_show_only_seen_changes:1;
	unsigned int update_partial:1;
	unsigned int cur_have_eoh:1;
	unsigned int cur_append_eoh:1;
	unsigned int first:1;
	unsigned int failed:1;
};

void imap_fetch_handlers_register(const struct imap_fetch_handler *handlers,
				  size_t count);

void imap_fetch_add_handler(struct imap_fetch_context *ctx,
			    imap_fetch_handler_t *handler, void *context);

struct imap_fetch_context *imap_fetch_init(struct client *client);
int imap_fetch_deinit(struct imap_fetch_context *ctx);
int imap_fetch_init_handler(struct imap_fetch_context *ctx, const char *name,
			    struct imap_arg **args);

void imap_fetch_begin(struct imap_fetch_context *ctx,
		      struct mail_search_arg *search_arg);
int imap_fetch(struct imap_fetch_context *ctx);

int fetch_body_section_init(struct imap_fetch_context *ctx, const char *name,
			    struct imap_arg **args);
int fetch_rfc822_init(struct imap_fetch_context *ctx, const char *name,
		      struct imap_arg **args);

#endif
