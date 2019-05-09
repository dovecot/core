#ifndef IMAP_FETCH_H
#define IMAP_FETCH_H

struct imap_fetch_context;

enum imap_fetch_handler_flags {
	IMAP_FETCH_HANDLER_FLAG_BUFFERED	= 0x01,
	IMAP_FETCH_HANDLER_FLAG_WANT_DEINIT	= 0x02
};

/* Returns 1 = ok, 0 = client output buffer full, call again, -1 = error.
   mail = NULL for deinit. */
typedef int imap_fetch_handler_t(struct imap_fetch_context *ctx,
				 struct mail *mail, void *context);

struct imap_fetch_init_context {
	struct imap_fetch_context *fetch_ctx;
	pool_t pool;

	const char *name;
	const struct imap_arg *args;

	const char *error;
};

struct imap_fetch_handler {
	const char *name;

	/* Returns FALSE and sets ctx->error if arg is invalid */
	bool (*init)(struct imap_fetch_init_context *ctx);
};

struct imap_fetch_context_handler {
	imap_fetch_handler_t *handler;
	void *context;

	const char *name;
	const char *nil_reply;

	bool buffered:1;
	bool want_deinit:1;
};

struct imap_fetch_qresync_args {
	const ARRAY_TYPE(uint32_t) *qresync_sample_seqset;
	const ARRAY_TYPE(uint32_t) *qresync_sample_uidset;
};

struct imap_fetch_state {
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;

	struct mail *cur_mail;
	unsigned int cur_handler;
	const char *cur_human_name;
	uoff_t cur_size;
	enum mail_fetch_field cur_size_field;
	string_t *cur_str;
	size_t cur_str_prefix_size;
	struct istream *cur_input;
	bool skip_cr;
	int (*cont_handler)(struct imap_fetch_context *ctx);
	uint64_t *cur_stats_sizep;

	bool fetching:1;
	bool seen_flags_changed:1;
	/* TRUE if the first FETCH parameter result hasn't yet been sent to
	   the IMAP client. Note that this doesn't affect buffered content in
	   cur_str until it gets flushed out. */
	bool cur_first:1;
	/* TRUE if the cur_str prefix has been flushed. More data may still
	   be added to it. */
	bool line_partial:1;
	bool skipped_expunged_msgs:1;
	bool failed:1;
};

struct imap_fetch_context {
	struct client *client;
	pool_t ctx_pool;
	const char *reason;

	enum mail_fetch_field fetch_data;
	ARRAY_TYPE(const_string) all_headers;

	ARRAY(struct imap_fetch_context_handler) handlers;
	unsigned int buffered_handlers_count;

	ARRAY_TYPE(keywords) tmp_keywords;

	struct imap_fetch_state state;
	ARRAY_TYPE(seq_range) fetch_failed_uids;
	unsigned int fetched_mails_count;

	enum mail_error error;
	const char *errstr;

	bool initialized:1;
	bool failures:1;
	bool flags_have_handler:1;
	bool flags_update_seen:1;
	bool flags_show_only_seen_changes:1;
	bool preview_command:1;
};

void imap_fetch_handlers_register(const struct imap_fetch_handler *handlers,
				  size_t count);
void imap_fetch_handler_unregister(const char *name);

void imap_fetch_add_handler(struct imap_fetch_init_context *ctx,
			    enum imap_fetch_handler_flags flags,
			    const char *nil_reply,
			    imap_fetch_handler_t *handler, void *context)
	ATTR_NULL(3, 5);
#define imap_fetch_add_handler(ctx, flags, nil_reply, handler, context) \
	  imap_fetch_add_handler(ctx, flags, nil_reply - \
		CALLBACK_TYPECHECK(handler, int (*)( \
			struct imap_fetch_context *, struct mail *, \
			typeof(context))), \
		(imap_fetch_handler_t *)handler, context)

int imap_fetch_att_list_parse(struct client *client, pool_t pool,
			      const struct imap_arg *list,
			      struct imap_fetch_context **fetch_ctx_r,
			      const char **client_error_r);

struct imap_fetch_context *
imap_fetch_alloc(struct client *client, pool_t pool, const char *reason);
void imap_fetch_free(struct imap_fetch_context **ctx);
bool imap_fetch_init_handler(struct imap_fetch_init_context *init_ctx);
void imap_fetch_init_nofail_handler(struct imap_fetch_context *ctx,
				    bool (*init)(struct imap_fetch_init_context *));
const struct imap_fetch_handler *imap_fetch_handler_lookup(const char *name);

void imap_fetch_begin(struct imap_fetch_context *ctx, struct mailbox *box,
		      struct mail_search_args *search_args);
int imap_fetch_send_vanished(struct client *client, struct mailbox *box,
			     const struct mail_search_args *search_args,
			     const struct imap_fetch_qresync_args *qresync_args);
/* Returns 1 if finished, 0 if more data is needed, -1 if error.
   When 0 is returned, line_partial=TRUE if literal is open and must be
   finished before anything else to client. */
int imap_fetch_more(struct imap_fetch_context *ctx,
		    struct client_command_context *cmd);
/* Like imap_fetch_more(), but don't check/update output_lock.
   The caller must handle this itself. */
int imap_fetch_more_no_lock_update(struct imap_fetch_context *ctx);
int imap_fetch_end(struct imap_fetch_context *ctx);
int imap_fetch_more(struct imap_fetch_context *ctx,
		    struct client_command_context *cmd);

bool imap_fetch_flags_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_modseq_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_uid_init(struct imap_fetch_init_context *ctx);

bool imap_fetch_body_section_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_rfc822_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_binary_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_preview_init(struct imap_fetch_init_context *ctx);
bool imap_fetch_snippet_init(struct imap_fetch_init_context *ctx);

void imap_fetch_handlers_init(void);
void imap_fetch_handlers_deinit(void);

#endif
