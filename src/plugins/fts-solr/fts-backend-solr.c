/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "unichar.h"
#include "iostream-ssl.h"
#include "http-url.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-search.h"
#include "fts-api.h"
#include "solr-connection.h"
#include "fts-solr-plugin.h"

#include <ctype.h>

#define SOLR_CMDBUF_SIZE (1024*64)
#define SOLR_CMDBUF_FLUSH_SIZE (SOLR_CMDBUF_SIZE-128)
#define SOLR_MAX_MULTI_ROWS 100000

/* If header is larger than this, truncate it. */
#define SOLR_HEADER_MAX_SIZE (1024*1024)
/* If SOLR_HEADER_MAX_SIZE was already reached, write still to individual
   header fields as long as they're smaller than this */
#define SOLR_HEADER_LINE_MAX_TRUNC_SIZE 1024

#define SOLR_QUERY_MAX_MAILBOX_COUNT 10
/* How often to flush indexing request to Solr before beginning a new one. */
#define SOLR_MAIL_FLUSH_INTERVAL 1000

struct solr_fts_backend {
	struct fts_backend backend;
	struct solr_connection *solr_conn;
};

struct solr_fts_field {
	char *key;
	string_t *value;
};

struct solr_fts_backend_update_context {
	struct fts_backend_update_context ctx;

	struct mailbox *cur_box;
	char box_guid[MAILBOX_GUID_HEX_LENGTH+1];

	struct solr_connection_post *post;
	uint32_t prev_uid;
	string_t *cmd, *cur_value, *cur_value2;
	string_t *cmd_expunge;
	ARRAY(struct solr_fts_field) fields;

	uint32_t last_indexed_uid;
	unsigned int mails_since_flush;

	bool tokenized_input:1;
	bool last_indexed_uid_set:1;
	bool body_open:1;
	bool documents_added:1;
	bool expunges:1;
	bool truncate_header:1;
};

static const char *solr_escape_chars = "+-&|!(){}[]^\"~*?:\\/ ";

static bool is_valid_xml_char(unichar_t chr)
{
	/* Valid characters in XML:

	   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
	   [#x10000-#x10FFFF]

	   This function gets called only for #x80 and higher */
	if (chr > 0xd7ff && chr < 0xe000)
		return FALSE;
	if (chr > 0xfffd && chr < 0x10000)
		return FALSE;
	return chr < 0x10ffff;
}

static size_t
xml_encode_data_max(string_t *dest, const unsigned char *data, size_t len,
		    unsigned int max_len)
{
	unichar_t chr;
	size_t i;

	i_assert(max_len > 0 || len == 0);

	if (max_len > len)
		max_len = len;
	for (i = 0; i < max_len; i++) {
		switch (data[i]) {
		case '&':
			str_append(dest, "&amp;");
			break;
		case '<':
			str_append(dest, "&lt;");
			break;
		case '>':
			str_append(dest, "&gt;");
			break;
		case '\t':
		case '\n':
		case '\r':
			/* exceptions to the following control char check */
			str_append_c(dest, data[i]);
			break;
		default:
			if (data[i] < 32) {
				/* SOLR doesn't like control characters.
				   replace them with spaces. */
				str_append_c(dest, ' ');
			} else if (data[i] >= 0x80) {
				/* make sure the character is valid for XML
				   so we don't get XML parser errors */
				unsigned int char_len =
					uni_utf8_get_char_n(data + i, len - i, &chr);
				if (char_len > 0 && is_valid_xml_char(chr))
					str_append_data(dest, data + i, char_len);
				else {
					str_append_data(dest, utf8_replacement_char,
							UTF8_REPLACEMENT_CHAR_LEN);
				}
				i += char_len - 1;
			} else {
				str_append_c(dest, data[i]);
			}
			break;
		}
	}
	return i;
}

static void
xml_encode_data(string_t *dest, const unsigned char *data, size_t len)
{
	(void)xml_encode_data_max(dest, data, len, len);
}

static void xml_encode(string_t *dest, const char *str)
{
	xml_encode_data(dest, (const unsigned char *)str, strlen(str));
}

static const char *solr_escape(const char *str)
{
	string_t *ret;
	unsigned int i;

	ret = t_str_new(strlen(str) + 16);
	for (i = 0; str[i] != '\0'; i++) {
		if (strchr(solr_escape_chars, str[i]) != NULL)
			str_append_c(ret, '\\');
		str_append_c(ret, str[i]);
	}
	return str_c(ret);
}

static void solr_quote_http(string_t *dest, const char *str)
{
	if (str[0] != '\0')
		http_url_escape_param(dest, solr_escape(str));
	else
		str_append(dest, "%22%22");
}

static struct fts_backend *fts_backend_solr_alloc(void)
{
	struct solr_fts_backend *backend;

	backend = i_new(struct solr_fts_backend, 1);
	backend->backend = fts_backend_solr;
	return &backend->backend;
}

static int
fts_backend_solr_init(struct fts_backend *_backend, const char **error_r)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT(_backend->ns->user);
	struct ssl_iostream_settings ssl_set;

	if (fuser == NULL) {
		*error_r = "Invalid fts_solr setting";
		return -1;
	}
	if (fuser->set.use_libfts) {
		/* change our flags so we get proper input */
		_backend->flags &= ~FTS_BACKEND_FLAG_FUZZY_SEARCH;
		_backend->flags |= FTS_BACKEND_FLAG_TOKENIZED_INPUT;
	}

	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(_backend->ns->user, &ssl_set);

	return solr_connection_init(&fuser->set, &ssl_set,
				    &backend->solr_conn, error_r);
}

static void fts_backend_solr_deinit(struct fts_backend *_backend)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;

	solr_connection_deinit(&backend->solr_conn);
	i_free(backend);
}

static int
get_last_uid_fallback(struct fts_backend *_backend, struct mailbox *box,
		      uint32_t *last_uid_r)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;
	const struct seq_range *uidvals;
	const char *box_guid;
	unsigned int count;
	struct solr_result **results;
	string_t *str;
	pool_t pool;
	int ret = 0;

	str = t_str_new(256);
	str_append(str, "wt=xml&fl=uid&rows=1&sort=uid+desc&q=");

	if (fts_mailbox_get_guid(box, &box_guid) < 0)
		return -1;

	str_printfa(str, "box:%s+AND+user:", box_guid);
	if (_backend->ns->owner != NULL)
		solr_quote_http(str, _backend->ns->owner->username);
	else
		str_append(str, "%22%22");

	pool = pool_alloconly_create("solr last uid lookup", 1024);
	if (solr_connection_select(backend->solr_conn, str_c(str),
				   pool, &results) < 0)
		ret = -1;
	else if (results[0] == NULL) {
		/* no UIDs */
		*last_uid_r = 0;
	} else {
		uidvals = array_get(&results[0]->uids, &count);
		i_assert(count > 0);
		if (count == 1 && uidvals[0].seq1 == uidvals[0].seq2) {
			*last_uid_r = uidvals[0].seq1;
		} else {
			i_error("fts_solr: Last UID lookup returned multiple rows");
			ret = -1;
		}
	}
	pool_unref(&pool);
	return ret;
}

static int
fts_backend_solr_get_last_uid(struct fts_backend *_backend,
			      struct mailbox *box, uint32_t *last_uid_r)
{
	struct fts_index_header hdr;

	if (fts_index_get_header(box, &hdr)) {
		*last_uid_r = hdr.last_indexed_uid;
		return 0;
	}

	/* either nothing has been indexed, or the index was corrupted.
	   do it the slow way. */
	if (get_last_uid_fallback(_backend, box, last_uid_r) < 0)
		return -1;

	fts_index_set_last_uid(box, *last_uid_r);
	return 0;
}

static struct fts_backend_update_context *
fts_backend_solr_update_init(struct fts_backend *_backend)
{
	struct solr_fts_backend_update_context *ctx;

	ctx = i_new(struct solr_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	ctx->tokenized_input =
		(_backend->flags & FTS_BACKEND_FLAG_TOKENIZED_INPUT) != 0;
	i_array_init(&ctx->fields, 16);
	return &ctx->ctx;
}

static void xml_encode_id(struct solr_fts_backend_update_context *ctx,
			  string_t *str, uint32_t uid)
{
	str_printfa(str, "%u/%s", uid, ctx->box_guid);
	if (ctx->ctx.backend->ns->owner != NULL) {
		str_append_c(str, '/');
		xml_encode(str, ctx->ctx.backend->ns->owner->username);
	}
}

static void
fts_backend_solr_doc_open(struct solr_fts_backend_update_context *ctx,
			  uint32_t uid)
{
	ctx->documents_added = TRUE;

	str_printfa(ctx->cmd, "<doc>"
		    "<field name=\"uid\">%u</field>"
		    "<field name=\"box\">%s</field>",
		    uid, ctx->box_guid);
	str_append(ctx->cmd, "<field name=\"user\">");
	if (ctx->ctx.backend->ns->owner != NULL)
		xml_encode(ctx->cmd, ctx->ctx.backend->ns->owner->username);
	str_append(ctx->cmd, "</field>");

	str_printfa(ctx->cmd, "<field name=\"id\">");
	xml_encode_id(ctx, ctx->cmd, uid);
	str_append(ctx->cmd, "</field>");
}

static string_t *
fts_solr_field_get(struct solr_fts_backend_update_context *ctx, const char *key)
{
	const struct solr_fts_field *field;
	struct solr_fts_field new_field;

	/* there are only a few fields. this lookup is fast enough. */
	array_foreach(&ctx->fields, field) {
		if (strcasecmp(field->key, key) == 0)
			return field->value;
	}

	i_zero(&new_field);
	new_field.key = str_lcase(i_strdup(key));
	new_field.value = str_new(default_pool, 128);
	array_push_back(&ctx->fields, &new_field);
	return new_field.value;
}

static void
fts_backend_solr_doc_close(struct solr_fts_backend_update_context *ctx)
{
	struct solr_fts_field *field;

	if (ctx->body_open) {
		ctx->body_open = FALSE;
		str_append(ctx->cmd, "</field>");
	}
	array_foreach_modifiable(&ctx->fields, field) {
		str_printfa(ctx->cmd, "<field name=\"%s\">", field->key);
		/* the values are already xml-escaped */
		str_append_str(ctx->cmd, field->value);
		str_append(ctx->cmd, "</field>");
		str_truncate(field->value, 0);
	}
	str_append(ctx->cmd, "</doc>");
}

static int
fts_backed_solr_build_flush(struct solr_fts_backend_update_context *ctx)
{
	if (ctx->post == NULL)
		return 0;

	fts_backend_solr_doc_close(ctx);
	str_append(ctx->cmd, "</add>");
	ctx->mails_since_flush = 0;

	solr_connection_post_more(ctx->post, str_data(ctx->cmd),
				  str_len(ctx->cmd));
	str_truncate(ctx->cmd, 0);
	return solr_connection_post_end(&ctx->post);
}

static void
fts_backend_solr_expunge_flush(struct solr_fts_backend_update_context *ctx)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)ctx->ctx.backend;

	str_append(ctx->cmd_expunge, "</delete>");
	(void)solr_connection_post(backend->solr_conn, str_c(ctx->cmd_expunge));
	str_truncate(ctx->cmd_expunge, 0);
	str_append(ctx->cmd_expunge, "<delete>");
}

static int
fts_backend_solr_update_deinit(struct fts_backend_update_context *_ctx)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_ctx->backend;
	struct solr_fts_field *field;
	const char *str;
	int ret = _ctx->failed ? -1 : 0;

	if (fts_backed_solr_build_flush(ctx) < 0)
		ret = -1;

	if (ctx->documents_added || ctx->expunges) {
		/* commit and wait until the documents we just indexed are
		   visible to the following search */
		if (ctx->expunges)
			fts_backend_solr_expunge_flush(ctx);
		str = t_strdup_printf("<commit softCommit=\"true\" waitSearcher=\"%s\"/>",
				      ctx->documents_added ? "true" : "false");
		if (solr_connection_post(backend->solr_conn, str) < 0)
			ret = -1;
	}

	str_free(&ctx->cmd);
	str_free(&ctx->cmd_expunge);
	array_foreach_modifiable(&ctx->fields, field) {
		str_free(&field->value);
		i_free(field->key);
	}
	array_free(&ctx->fields);
	i_free(ctx);
	return ret;
}

static void
fts_backend_solr_update_set_mailbox(struct fts_backend_update_context *_ctx,
				    struct mailbox *box)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	const char *box_guid;

	if (ctx->prev_uid != 0) {
		i_assert(ctx->cur_box != NULL);

		/* flush solr between mailboxes, so we don't wrongly update
		   last_uid before we know it has succeeded */
		if (fts_backed_solr_build_flush(ctx) < 0)
			_ctx->failed = TRUE;
		else if (!_ctx->failed)
			fts_index_set_last_uid(ctx->cur_box, ctx->prev_uid);
		ctx->prev_uid = 0;
	}

	if (box != NULL) {
		if (fts_mailbox_get_guid(box, &box_guid) < 0)
			_ctx->failed = TRUE;

		i_assert(strlen(box_guid) == sizeof(ctx->box_guid)-1);
		memcpy(ctx->box_guid, box_guid, sizeof(ctx->box_guid)-1);
	} else {
		memset(ctx->box_guid, 0, sizeof(ctx->box_guid));
	}
	ctx->cur_box = box;
}

static void
fts_backend_solr_update_expunge(struct fts_backend_update_context *_ctx,
				uint32_t uid)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	struct fts_index_header hdr;

	if (!ctx->last_indexed_uid_set) {
		if (!fts_index_get_header(ctx->cur_box, &hdr))
			ctx->last_indexed_uid = 0;
		else
			ctx->last_indexed_uid = hdr.last_indexed_uid;
		ctx->last_indexed_uid_set = TRUE;
	}
	if (ctx->last_indexed_uid == 0 ||
	    uid > ctx->last_indexed_uid + 100) {
		/* don't waste time asking Solr to expunge a message that is
		   highly unlikely to be indexed at this time. */
		return;
	}
	if (!ctx->expunges) {
		ctx->expunges = TRUE;
		ctx->cmd_expunge = str_new(default_pool, 1024);
		str_append(ctx->cmd_expunge, "<delete>");
	}

	if (str_len(ctx->cmd_expunge) >= SOLR_CMDBUF_FLUSH_SIZE)
		fts_backend_solr_expunge_flush(ctx);

	str_append(ctx->cmd_expunge, "<id>");
	xml_encode_id(ctx, ctx->cmd_expunge, uid);
	str_append(ctx->cmd_expunge, "</id>");
}

static void
fts_backend_solr_uid_changed(struct solr_fts_backend_update_context *ctx,
			     uint32_t uid)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)ctx->ctx.backend;

	if (ctx->mails_since_flush++ >= SOLR_MAIL_FLUSH_INTERVAL) {
		if (fts_backed_solr_build_flush(ctx) < 0)
			ctx->ctx.failed = TRUE;
	}
	if (ctx->post == NULL) {
		if (ctx->cmd == NULL)
			ctx->cmd = str_new(default_pool, SOLR_CMDBUF_SIZE);
		ctx->post = solr_connection_post_begin(backend->solr_conn);
		str_append(ctx->cmd, "<add>");
	} else {
		fts_backend_solr_doc_close(ctx);
	}
	ctx->prev_uid = uid;
	ctx->truncate_header = FALSE;
	fts_backend_solr_doc_open(ctx, uid);
}

static bool
fts_backend_solr_update_set_build_key(struct fts_backend_update_context *_ctx,
				      const struct fts_backend_build_key *key)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;

	if (key->uid != ctx->prev_uid)
		fts_backend_solr_uid_changed(ctx, key->uid);

	switch (key->type) {
	case FTS_BACKEND_BUILD_KEY_HDR:
		if (fts_header_want_indexed(key->hdr_name)) {
			ctx->cur_value2 =
				fts_solr_field_get(ctx, key->hdr_name);
		}
		/* fall through */
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
		ctx->cur_value = fts_solr_field_get(ctx, "hdr");
		xml_encode(ctx->cur_value, key->hdr_name);
		str_append(ctx->cur_value, ": ");
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		if (!ctx->body_open) {
			ctx->body_open = TRUE;
			str_append(ctx->cmd, "<field name=\"body\">");
		}
		ctx->cur_value = ctx->cmd;
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY:
		i_unreached();
	}
	return TRUE;
}

static void
fts_backend_solr_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;

	/* There can be multiple duplicate keys (duplicate header lines,
	   multiple MIME body parts). Make sure they are separated by
	   whitespace. */
	str_append_c(ctx->cur_value, '\n');
	ctx->cur_value = NULL;
	if (ctx->cur_value2 != NULL) {
		str_append_c(ctx->cur_value2, '\n');
		ctx->cur_value2 = NULL;
	}
}

static int
fts_backend_solr_update_build_more(struct fts_backend_update_context *_ctx,
				   const unsigned char *data, size_t size)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	size_t len;

	if (_ctx->failed)
		return -1;

	if (ctx->cur_value2 == NULL && ctx->cur_value == ctx->cmd) {
		/* we're writing to message body. if size is huge,
		   flush it once in a while */
		while (size >= SOLR_CMDBUF_FLUSH_SIZE) {
			if (str_len(ctx->cmd) >= SOLR_CMDBUF_FLUSH_SIZE) {
				solr_connection_post_more(ctx->post,
							  str_data(ctx->cmd),
							  str_len(ctx->cmd));
				str_truncate(ctx->cmd, 0);
			}
			len = xml_encode_data_max(ctx->cmd, data, size,
						  SOLR_CMDBUF_FLUSH_SIZE -
						  str_len(ctx->cmd));
			i_assert(len > 0);
			i_assert(len <= size);
			data += len;
			size -= len;
		}
		xml_encode_data(ctx->cmd, data, size);
		if (ctx->tokenized_input)
			str_append_c(ctx->cmd, ' ');
	} else {
		if (!ctx->truncate_header) {
			xml_encode_data(ctx->cur_value, data, size);
			if (ctx->tokenized_input)
				str_append_c(ctx->cur_value, ' ');
		}
		if (ctx->cur_value2 != NULL &&
		    (!ctx->truncate_header ||
		     str_len(ctx->cur_value2) < SOLR_HEADER_LINE_MAX_TRUNC_SIZE)) {
			xml_encode_data(ctx->cur_value2, data, size);
			if (ctx->tokenized_input)
				str_append_c(ctx->cur_value2, ' ');
		}
	}

	if (str_len(ctx->cmd) >= SOLR_CMDBUF_FLUSH_SIZE) {
		solr_connection_post_more(ctx->post, str_data(ctx->cmd),
					  str_len(ctx->cmd));
		str_truncate(ctx->cmd, 0);
	}
	if (!ctx->truncate_header &&
	    str_len(ctx->cur_value) >= SOLR_HEADER_MAX_SIZE) {
		/* a large header */
		i_assert(ctx->cur_value != ctx->cmd);

		i_warning("fts-solr(%s): Mailbox %s UID=%u header size is huge, truncating",
			  ctx->cur_box->storage->user->username,
			  mailbox_get_vname(ctx->cur_box), ctx->prev_uid);
		ctx->truncate_header = TRUE;
	}
	return 0;
}

static int fts_backend_solr_refresh(struct fts_backend *backend ATTR_UNUSED)
{
	return 0;
}

static int fts_backend_solr_rescan(struct fts_backend *backend)
{
	/* FIXME: proper rescan needed. for now we'll just reset the
	   last-uids */
	return fts_backend_reset_last_uids(backend);
}

static int fts_backend_solr_optimize(struct fts_backend *backend ATTR_UNUSED)
{
	return 0;
}

static bool solr_need_escaping(const char *str)
{
	for (; *str != '\0'; str++) {
		if (strchr(solr_escape_chars, *str) != NULL)
			return TRUE;
	}
	return FALSE;
}

static void solr_add_str_arg(string_t *str, struct mail_search_arg *arg)
{
	/* currently we'll just disable fuzzy searching if there are any
	   parameters that need escaping. solr doesn't seem to give good
	   fuzzy results even if we did escape them.. */
	if (!arg->fuzzy || arg->value.str[0] == '\0' ||
	    solr_need_escaping(arg->value.str))
		solr_quote_http(str, arg->value.str);
	else {
		http_url_escape_param(str, arg->value.str);
		str_append_c(str, '~');
	}
}

static bool
solr_add_definite_query(string_t *str, struct mail_search_arg *arg)
{
	if (arg->no_fts)
		return FALSE;
	switch (arg->type) {
	case SEARCH_TEXT: {
		if (arg->match_not)
			str_append_c(str, '-');
		str_append(str, "(hdr:");
		solr_add_str_arg(str, arg);
		str_append(str, "+OR+body:");
		solr_add_str_arg(str, arg);
		str_append(str, ")");
		break;
	}
	case SEARCH_BODY:
		if (arg->match_not)
			str_append_c(str, '-');
		str_append(str, "body:");
		solr_add_str_arg(str, arg);
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (!fts_header_want_indexed(arg->hdr_field_name))
			return FALSE;

		if (arg->match_not)
			str_append_c(str, '-');
		str_append(str, t_str_lcase(arg->hdr_field_name));
		str_append_c(str, ':');
		solr_add_str_arg(str, arg);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static bool
solr_add_definite_query_args(string_t *str, struct mail_search_arg *arg,
			     bool and_args)
{
	size_t last_len;

	last_len = str_len(str);
	for (; arg != NULL; arg = arg->next) {
		if (solr_add_definite_query(str, arg)) {
			arg->match_always = TRUE;
			last_len = str_len(str);
			if (and_args)
				str_append(str, "+AND+");
			else
				str_append(str, "+OR+");
		}
	}
	if (str_len(str) == last_len)
		return FALSE;

	str_truncate(str, last_len);
	return TRUE;
}

static bool
solr_add_maybe_query(string_t *str, struct mail_search_arg *arg)
{
	if (arg->no_fts)
		return FALSE;
	switch (arg->type) {
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (fts_header_want_indexed(arg->hdr_field_name))
			return FALSE;
		if (arg->match_not) {
			/* all matches would be definite, but all non-matches
			   would be maybies. too much trouble to optimize. */
			return FALSE;
		}

		/* we can check if the search key exists in some header and
		   filter out the messages that have no chance of matching */
		str_append(str, "hdr:");
		if (*arg->value.str != '\0')
			solr_quote_http(str, arg->value.str);
		else {
			/* checking potential existence of the header name */
			solr_quote_http(str, t_str_lcase(arg->hdr_field_name));
		}
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static bool
solr_add_maybe_query_args(string_t *str, struct mail_search_arg *arg,
			  bool and_args)
{
	size_t last_len;

	last_len = str_len(str);
	for (; arg != NULL; arg = arg->next) {
		if (solr_add_maybe_query(str, arg)) {
			arg->match_always = TRUE;
			last_len = str_len(str);
			if (and_args)
				str_append(str, "+AND+");
			else
				str_append(str, "+OR+");
		}
	}
	if (str_len(str) == last_len)
		return FALSE;

	str_truncate(str, last_len);
	return TRUE;
}

static int solr_search(struct fts_backend *_backend, string_t *str,
		       const char *box_guid, ARRAY_TYPE(seq_range) *uids_r,
		       ARRAY_TYPE(fts_score_map) *scores_r)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;
	pool_t pool = pool_alloconly_create("fts solr search", 1024);
	struct solr_result **results;
	int ret;

	/* use a separate filter query for selecting the mailbox. it shouldn't
	   affect the score and there could be some caching benefits too. */
	str_printfa(str, "&fq=%%2Bbox:%s+%%2Buser:", box_guid);
	if (_backend->ns->owner != NULL)
		solr_quote_http(str, _backend->ns->owner->username);
	else
		str_append(str, "%22%22");

	ret = solr_connection_select(backend->solr_conn, str_c(str),
				     pool, &results);
	if (ret == 0 && results[0] != NULL) {
		array_append_array(uids_r, &results[0]->uids);
		array_append_array(scores_r, &results[0]->scores);
	}
	pool_unref(&pool);
	return ret;
}

static int
fts_backend_solr_lookup(struct fts_backend *_backend, struct mailbox *box,
			struct mail_search_arg *args,
			enum fts_lookup_flags flags,
			struct fts_result *result)
{
	bool and_args = (flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0;
	struct mailbox_status status;
	string_t *str;
	const char *box_guid;
	size_t prefix_len;

	if (fts_mailbox_get_guid(box, &box_guid) < 0)
		return -1;
	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);

	str = t_str_new(256);
	str_printfa(str, "wt=xml&fl=uid,score&rows=%u&sort=uid+asc&q=%%7b!lucene+q.op%%3dAND%%7d",
		    status.uidnext);
	prefix_len = str_len(str);

	if (solr_add_definite_query_args(str, args, and_args)) {
		ARRAY_TYPE(seq_range) *uids_arr =
			(flags & FTS_LOOKUP_FLAG_NO_AUTO_FUZZY) == 0 ?
			&result->definite_uids : &result->maybe_uids;
		if (solr_search(_backend, str, box_guid,
				uids_arr, &result->scores) < 0)
			return -1;
	}
	str_truncate(str, prefix_len);
	if (solr_add_maybe_query_args(str, args, and_args)) {
		if (solr_search(_backend, str, box_guid,
				&result->maybe_uids, &result->scores) < 0)
			return -1;
	}               
	result->scores_sorted = TRUE;
	return 0;
}

static int
solr_search_multi(struct fts_backend *_backend, string_t *str,
		  struct mailbox *const boxes[], enum fts_lookup_flags flags,
		  struct fts_multi_result *result)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;
	struct solr_result **solr_results;
	struct fts_result *fts_result;
	ARRAY(struct fts_result) fts_results;
	HASH_TABLE(char *, struct mailbox *) mailboxes;
	struct mailbox *box;
	const char *box_guid;
	unsigned int i;
	size_t len;
	bool search_all_mailboxes;

	/* use a separate filter query for selecting the mailbox. it shouldn't
	   affect the score and there could be some caching benefits too. */
	str_append(str, "&fq=%2Buser:");
	if (_backend->ns->owner != NULL)
		solr_quote_http(str, _backend->ns->owner->username);
	else
		str_append(str, "%22%22");

	hash_table_create(&mailboxes, default_pool, 0, str_hash, strcmp);
	for (i = 0; boxes[i] != NULL; i++) ;
	search_all_mailboxes = i > SOLR_QUERY_MAX_MAILBOX_COUNT;
	if (!search_all_mailboxes)
		str_append(str, "+%2B(");
	len = str_len(str);

	for (i = 0; boxes[i] != NULL; i++) {
		if (fts_mailbox_get_guid(boxes[i], &box_guid) < 0)
			continue;

		if (!search_all_mailboxes) {
			if (str_len(str) != len)
				str_append(str, "+OR+");
			str_printfa(str, "box:%s", box_guid);
		}
		hash_table_insert(mailboxes, t_strdup_noconst(box_guid),
				  boxes[i]);
	}
	if (!search_all_mailboxes)
		str_append_c(str, ')');

	if (solr_connection_select(backend->solr_conn, str_c(str),
				   result->pool, &solr_results) < 0) {
		hash_table_destroy(&mailboxes);
		return -1;
	}

	p_array_init(&fts_results, result->pool, 32);
	for (i = 0; solr_results[i] != NULL; i++) {
		box = hash_table_lookup(mailboxes, solr_results[i]->box_id);
		if (box == NULL) {
			if (!search_all_mailboxes) {
				i_warning("fts_solr: Lookup returned unexpected mailbox "
					  "with guid=%s", solr_results[i]->box_id);
			}
			continue;
		}
		fts_result = array_append_space(&fts_results);
		fts_result->box = box;
		if ((flags & FTS_LOOKUP_FLAG_NO_AUTO_FUZZY) == 0)
			fts_result->definite_uids = solr_results[i]->uids;
		else
			fts_result->maybe_uids = solr_results[i]->uids;
		fts_result->scores = solr_results[i]->scores;
		fts_result->scores_sorted = TRUE;
	}
	array_append_zero(&fts_results);
	result->box_results = array_first_modifiable(&fts_results);
	hash_table_destroy(&mailboxes);
	return 0;
}

static int
fts_backend_solr_lookup_multi(struct fts_backend *backend,
			      struct mailbox *const boxes[],
			      struct mail_search_arg *args,
			      enum fts_lookup_flags flags,
			      struct fts_multi_result *result)
{
	bool and_args = (flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0;
	string_t *str;

	str = t_str_new(256);
	str_printfa(str, "wt=xml&fl=box,uid,score&rows=%u&sort=box+asc,uid+asc&q=%%7b!lucene+q.op%%3dAND%%7d",
		    SOLR_MAX_MULTI_ROWS);

	if (solr_add_definite_query_args(str, args, and_args)) {
		if (solr_search_multi(backend, str, boxes, flags, result) < 0)
			return -1;
	}
	/* FIXME: maybe_uids could be handled also with some more work.. */
	return 0;
}

struct fts_backend fts_backend_solr = {
	.name = "solr",
	.flags = FTS_BACKEND_FLAG_FUZZY_SEARCH,

	{
		fts_backend_solr_alloc,
		fts_backend_solr_init,
		fts_backend_solr_deinit,
		fts_backend_solr_get_last_uid,
		fts_backend_solr_update_init,
		fts_backend_solr_update_deinit,
		fts_backend_solr_update_set_mailbox,
		fts_backend_solr_update_expunge,
		fts_backend_solr_update_set_build_key,
		fts_backend_solr_update_unset_build_key,
		fts_backend_solr_update_build_more,
		fts_backend_solr_refresh,
		fts_backend_solr_rescan,
		fts_backend_solr_optimize,
		fts_backend_default_can_lookup,
		fts_backend_solr_lookup,
		fts_backend_solr_lookup_multi,
		NULL
	}
};
