#ifndef IMAP_FETCH_H
#define IMAP_FETCH_H

struct imap_fetch_context;

/* Returns 1 = ok, 0 = client output buffer full, call again, -1 = error.
   mail = NULL for deinit. */
typedef int imap_fetch_handler_t(struct imap_fetch_context *ctx,
				 struct mail *mail, void *context);

struct imap_fetch_handler {
	const char *name;

	/* Returns FALSE if arg is invalid. */
	bool (*init)(struct imap_fetch_context *ctx, const char *name,
		     const struct imap_arg **args);
};

struct imap_fetch_context_handler {
	imap_fetch_handler_t *handler;
	void *context;

	const char *name;
	const char *nil_reply;

	unsigned int buffered:1;
	unsigned int want_deinit:1;
};

struct imap_fetch_context {
	struct client *client;
	struct client_command_context *cmd;
	struct mailbox *box;

	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;

	enum mail_fetch_field fetch_data;
	ARRAY_TYPE(const_string) all_headers;
        struct mailbox_header_lookup_ctx *all_headers_ctx;

	ARRAY_DEFINE(handlers, struct imap_fetch_context_handler);
	unsigned int buffered_handlers_count;

	struct mail *cur_mail;
	unsigned int cur_handler;
	const char *cur_name;
	uoff_t cur_size, cur_offset;
	enum mail_fetch_field cur_size_field;
	string_t *cur_str;
	struct istream *cur_input;
	bool skip_cr;
	int (*cont_handler)(struct imap_fetch_context *ctx);

	const ARRAY_TYPE(uint32_t) *qresync_sample_seqset;
	const ARRAY_TYPE(uint32_t) *qresync_sample_uidset;

	ARRAY_TYPE(keywords) tmp_keywords;
	unsigned int select_counter;

	unsigned int flags_have_handler:1;
	unsigned int flags_update_seen:1;
	unsigned int seen_flags_changed:1;
	unsigned int flags_show_only_seen_changes:1;
	unsigned int update_partial:1;
	unsigned int cur_append_eoh:1;
	unsigned int first:1;
	unsigned int line_partial:1;
	unsigned int line_finished:1;
	unsigned int partial_fetch:1;
	unsigned int send_vanished:1;
	unsigned int failed:1;
};

void imap_fetch_handlers_register(const struct imap_fetch_handler *handlers,
				  size_t count);

void imap_fetch_add_handler(struct imap_fetch_context *ctx,
			    bool buffered, bool want_deinit,
			    const char *name, const char *nil_reply,
			    imap_fetch_handler_t *handler, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define imap_fetch_add_handler(ctx, buffered, want_deinit, name, nil_reply, \
				 handler, context) \
	({(void)(1 ? 0 : handler((struct imap_fetch_context *)NULL, \
				 (struct mail *)NULL, context)); \
	  imap_fetch_add_handler(ctx, buffered, want_deinit, name, nil_reply, \
		(imap_fetch_handler_t *)handler, context); })
#else
#  define imap_fetch_add_handler(ctx, buffered, want_deinit, name, nil_reply, \
				 handler, context) \
	  imap_fetch_add_handler(ctx, buffered, want_deinit, name, nil_reply, \
		(imap_fetch_handler_t *)handler, context)
#endif

struct imap_fetch_context *
imap_fetch_init(struct client_command_context *cmd, struct mailbox *box);
int imap_fetch_deinit(struct imap_fetch_context *ctx);
bool imap_fetch_init_handler(struct imap_fetch_context *ctx, const char *name,
			     const struct imap_arg **args);

bool imap_fetch_add_changed_since(struct imap_fetch_context *ctx,
				  uint64_t modseq);

int imap_fetch_begin(struct imap_fetch_context *ctx);
int imap_fetch_more(struct imap_fetch_context *ctx);

bool fetch_body_section_init(struct imap_fetch_context *ctx, const char *name,
			     const struct imap_arg **args);
bool fetch_rfc822_init(struct imap_fetch_context *ctx, const char *name,
		       const struct imap_arg **args);

void imap_fetch_handlers_init(void);
void imap_fetch_handlers_deinit(void);

#endif
