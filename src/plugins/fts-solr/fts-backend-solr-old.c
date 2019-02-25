/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "unichar.h"
#include "iostream-ssl.h"
#include "http-url.h"
#include "imap-utf7.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-search.h"
#include "fts-api.h"
#include "solr-connection.h"
#include "fts-solr-plugin.h"

#include <ctype.h>

#define SOLR_CMDBUF_SIZE (1024*64)
#define SOLR_MAX_MULTI_ROWS 100000

struct solr_fts_backend {
	struct fts_backend backend;
	struct solr_connection *solr_conn;
	char *id_username, *id_namespace;
	struct mail_namespace *default_ns;
};

struct solr_fts_backend_update_context {
	struct fts_backend_update_context ctx;

	struct mailbox *cur_box;
	char *id_box_name;

	struct solr_connection_post *post;
	uint32_t prev_uid, uid_validity;
	string_t *cmd, *hdr;

	bool headers_open;
	bool body_open;
	bool documents_added;
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

static void
xml_encode_data(string_t *dest, const unsigned char *data, size_t len)
{
	unichar_t chr;
	size_t i;

	for (i = 0; i < len; i++) {
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
}

static void xml_encode(string_t *dest, const char *str)
{
	xml_encode_data(dest, (const unsigned char *)str, strlen(str));
}

static const char *solr_escape_id_str(const char *str)
{
	string_t *tmp;
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p == '/' || *p == '!')
			break;
	}
	if (*p == '\0')
		return str;

	tmp = t_str_new(64);
	for (p = str; *p != '\0'; p++) {
		switch (*p) {
		case '/':
			str_append(tmp, "!\\");
			break;
		case '!':
			str_append(tmp, "!!");
			break;
		default:
			str_append_c(tmp, *p);
			break;
		}
	}
	return str_c(tmp);
}

static const char *solr_escape(const char *str)
{
	string_t *ret;
	unsigned int i;

	if (str[0] == '\0')
		return "\"\"";

	ret = t_str_new(strlen(str) + 16);
	for (i = 0; str[i] != '\0'; i++) {
		if (strchr(solr_escape_chars, str[i]) != NULL)
			str_append_c(ret, '\\');
		str_append_c(ret, str[i]);
	}
	return str_c(ret);
}

static void solr_quote(string_t *dest, const char *str)
{
	str_append(dest, solr_escape(str));
}

static void solr_quote_http(string_t *dest, const char *str)
{
	http_url_escape_param(dest, solr_escape(str));
}

static void fts_solr_set_default_ns(struct solr_fts_backend *backend)
{
	struct mail_namespace *ns = backend->backend.ns;
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT_REQUIRE(ns->user);
	const struct fts_solr_settings *set = &fuser->set;
	const char *str;

	if (backend->default_ns != NULL)
		return;

	if (set->default_ns_prefix != NULL) {
		backend->default_ns =
			mail_namespace_find_prefix(ns->user->namespaces,
						   set->default_ns_prefix);
		if (backend->default_ns == NULL) {
			i_error("fts_solr: default_ns setting points to "
				"nonexistent namespace");
		}
	}
	if (backend->default_ns == NULL) {
		backend->default_ns =
			mail_namespace_find_inbox(ns->user->namespaces);
	}
	while (backend->default_ns->alias_for != NULL)
		backend->default_ns = backend->default_ns->alias_for;

	if (ns != backend->default_ns) {
		str = solr_escape_id_str(ns->prefix);
		backend->id_namespace = i_strdup(str);
	}
}

static void fts_box_name_get_root(struct mail_namespace **ns, const char **name)
{
	struct mail_namespace *orig_ns = *ns;

	while ((*ns)->alias_for != NULL)
		*ns = (*ns)->alias_for;

	if (**name == '\0' && *ns != orig_ns &&
	    ((*ns)->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* ugly workaround to allow selecting INBOX from a Maildir/
		   when it's not in the inbox=yes namespace. */
		*name = "INBOX";
	}
}

static const char *
fts_box_get_root(struct mailbox *box, struct mail_namespace **ns_r)
{
	struct mail_namespace *ns = mailbox_get_namespace(box);
	const char *name;

	if (t_imap_utf8_to_utf7(box->name, &name) < 0)
		i_unreached();

	fts_box_name_get_root(&ns, &name);
	*ns_r = ns;
	return name;
}

static struct fts_backend *fts_backend_solr_alloc(void)
{
	struct solr_fts_backend *backend;

	backend = i_new(struct solr_fts_backend, 1);
	backend->backend = fts_backend_solr_old;
	return &backend->backend;
}

static int
fts_backend_solr_init(struct fts_backend *_backend, const char **error_r)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT(_backend->ns->user);
	struct ssl_iostream_settings ssl_set;
	const char *str;

	if (fuser == NULL) {
		*error_r = "Invalid fts_solr setting";
		return -1;
	}

	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(_backend->ns->user, &ssl_set);

	if (solr_connection_init(&fuser->set, &ssl_set,
				 &backend->solr_conn, error_r) < 0)
		return -1;

	str = solr_escape_id_str(_backend->ns->user->username);
	backend->id_username = i_strdup(str);
	return 0;
}

static void fts_backend_solr_deinit(struct fts_backend *_backend)
{
	struct solr_fts_backend *backend = (struct solr_fts_backend *)_backend;

	solr_connection_deinit(&backend->solr_conn);
	i_free(backend->id_namespace);
	i_free(backend->id_username);
	i_free(backend);
}

static void
solr_add_ns_query(string_t *str, struct solr_fts_backend *backend,
		  struct mail_namespace *ns, bool neg)
{
	while (ns->alias_for != NULL)
		ns = ns->alias_for;

	if (ns == backend->default_ns || *ns->prefix == '\0') {
		if (!neg)
			str_append(str, " -ns:[* TO *]");
		else
			str_append(str, " +ns:[* TO *]");
	} else {
		if (!neg)
			str_append(str, " +ns:");
		else
			str_append(str, " -ns:");
		solr_quote(str, ns->prefix);
	}
}

static void
solr_add_ns_query_http(string_t *str, struct solr_fts_backend *backend,
		       struct mail_namespace *ns)
{
	string_t *tmp;

	tmp = t_str_new(64);
	solr_add_ns_query(tmp, backend, ns, FALSE);
	http_url_escape_param(str, str_c(tmp));
}

static int
fts_backend_solr_get_last_uid_fallback(struct solr_fts_backend *backend,
				       struct mailbox *box,
				       uint32_t *last_uid_r)
{
	struct mail_namespace *ns;
	struct mailbox_status status;
	struct solr_result **results;
	const struct seq_range *uidvals;
	const char *box_name;
	unsigned int count;
	string_t *str;
	pool_t pool;
	int ret = 0;

	str = t_str_new(256);
	str_append(str, "fl=uid&rows=1&sort=uid+desc&q=");

	box_name = fts_box_get_root(box, &ns);

	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &status);
	str_printfa(str, "uidv:%u+AND+box:", status.uidvalidity);
	solr_quote_http(str, box_name);
	solr_add_ns_query_http(str, backend, ns);
	str_append(str, "+AND+user:");
	solr_quote_http(str, ns->user->username);

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
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_backend;
	struct fts_index_header hdr;

	if (fts_index_get_header(box, &hdr)) {
		*last_uid_r = hdr.last_indexed_uid;
		return 0;
	}

	/* either nothing has been indexed, or the index was corrupted.
	   do it the slow way. */
	if (fts_backend_solr_get_last_uid_fallback(backend, box, last_uid_r) < 0)
		return -1;

	fts_index_set_last_uid(box, *last_uid_r);
	return 0;
}

static struct fts_backend_update_context *
fts_backend_solr_update_init(struct fts_backend *_backend)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_backend;
	struct solr_fts_backend_update_context *ctx;

	ctx = i_new(struct solr_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	ctx->cmd = str_new(default_pool, SOLR_CMDBUF_SIZE);
	ctx->hdr = str_new(default_pool, 4096);
	fts_solr_set_default_ns(backend);
	return &ctx->ctx;
}

static void xml_encode_id(struct solr_fts_backend_update_context *ctx,
			  string_t *str, uint32_t uid)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)ctx->ctx.backend;

	if (uid != 0)
		str_printfa(str, "%u/", uid);
	else
		str_append(str, "L/");

	if (backend->id_namespace != NULL) {
		xml_encode(str, backend->id_namespace);
		str_append_c(str, '/');
	}
	str_printfa(str, "%u/", ctx->uid_validity);
	xml_encode(str, backend->id_username);
	str_append_c(str, '/');
	xml_encode(str, ctx->id_box_name);
}

static void
fts_backend_solr_add_doc_prefix(struct solr_fts_backend_update_context *ctx,
				uint32_t uid)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)ctx->ctx.backend;
	struct mailbox *box = ctx->cur_box;
	struct mail_namespace *ns;
	const char *box_name;

	ctx->documents_added = TRUE;

	str_printfa(ctx->cmd, "<doc>"
		    "<field name=\"uid\">%u</field>"
		    "<field name=\"uidv\">%u</field>",
		    uid, ctx->uid_validity);

	box_name = fts_box_get_root(box, &ns);

	if (ns != backend->default_ns) {
		str_append(ctx->cmd, "<field name=\"ns\">");
		xml_encode(ctx->cmd, ns->prefix);
		str_append(ctx->cmd, "</field>");
	}
	str_append(ctx->cmd, "<field name=\"box\">");
	xml_encode(ctx->cmd, box_name);
	str_append(ctx->cmd, "</field><field name=\"user\">");
	xml_encode(ctx->cmd, ns->user->username);
	str_append(ctx->cmd, "</field>");
}

static int
fts_backed_solr_build_commit(struct solr_fts_backend_update_context *ctx)
{
	if (ctx->post == NULL)
		return 0;

	str_append(ctx->cmd, "</doc></add>");

	solr_connection_post_more(ctx->post, str_data(ctx->cmd),
				  str_len(ctx->cmd));
	return solr_connection_post_end(&ctx->post);
}

static int
fts_backend_solr_update_deinit(struct fts_backend_update_context *_ctx)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_ctx->backend;
	const char *str;
	int ret;

	ret = fts_backed_solr_build_commit(ctx);

	/* commit and wait until the documents we just indexed are
	   visible to the following search */
	str = t_strdup_printf("<commit waitFlush=\"false\" "
			      "waitSearcher=\"%s\"/>",
			      ctx->documents_added ? "true" : "false");
	if (solr_connection_post(backend->solr_conn, str) < 0)
		ret = -1;

	str_free(&ctx->cmd);
	str_free(&ctx->hdr);
	i_free(ctx->id_box_name);
	i_free(ctx);
	return ret;
}

static void
fts_backend_solr_update_set_mailbox(struct fts_backend_update_context *_ctx,
				    struct mailbox *box)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	struct mailbox_status status;
	struct mail_namespace *ns;

	if (ctx->prev_uid != 0) {
		fts_index_set_last_uid(ctx->cur_box, ctx->prev_uid);
		ctx->prev_uid = 0;
	}

	ctx->cur_box = box;
	ctx->uid_validity = 0;
	i_free_and_null(ctx->id_box_name);

	if (box != NULL) {
		ctx->id_box_name = i_strdup(fts_box_get_root(box, &ns));

		mailbox_get_open_status(box, STATUS_UIDVALIDITY, &status);
		ctx->uid_validity = status.uidvalidity;
	}
}

static void
fts_backend_solr_update_expunge(struct fts_backend_update_context *_ctx,
				uint32_t uid)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_ctx->backend;

	T_BEGIN {
		string_t *cmd;

		cmd = t_str_new(256);
		str_append(cmd, "<delete><id>");
		xml_encode_id(ctx, cmd, uid);
		str_append(cmd, "</id></delete>");

		(void)solr_connection_post(backend->solr_conn, str_c(cmd));
	} T_END;
}

static void
fts_backend_solr_uid_changed(struct solr_fts_backend_update_context *ctx,
			     uint32_t uid)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)ctx->ctx.backend;

	if (ctx->post == NULL) {
		i_assert(ctx->prev_uid == 0);

		ctx->post = solr_connection_post_begin(backend->solr_conn);
		str_append(ctx->cmd, "<add>");
	} else {
		ctx->headers_open = FALSE;
		if (ctx->body_open) {
			ctx->body_open = FALSE;
			str_append(ctx->cmd, "</field>");
		}
		str_append(ctx->cmd, "<field name=\"hdr\">");
		str_append_str(ctx->cmd, ctx->hdr);
		str_append(ctx->cmd, "</field>");
		str_truncate(ctx->hdr, 0);

		str_append(ctx->cmd, "</doc>");
	}
	ctx->prev_uid = uid;

	fts_backend_solr_add_doc_prefix(ctx, uid);
	str_printfa(ctx->cmd, "<field name=\"id\">");
	xml_encode_id(ctx, ctx->cmd, uid);
	str_append(ctx->cmd, "</field>");
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
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
		xml_encode(ctx->hdr, key->hdr_name);
		str_append(ctx->hdr, ": ");
		ctx->headers_open = TRUE;
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		ctx->headers_open = FALSE;
		if (!ctx->body_open) {
			ctx->body_open = TRUE;
			str_append(ctx->cmd, "<field name=\"body\">");
		}
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

	if (ctx->headers_open)
		str_append_c(ctx->hdr, '\n');
	else {
		i_assert(ctx->body_open);
		str_append_c(ctx->cmd, '\n');
	}
}

static int
fts_backend_solr_update_build_more(struct fts_backend_update_context *_ctx,
				   const unsigned char *data, size_t size)
{
	struct solr_fts_backend_update_context *ctx =
		(struct solr_fts_backend_update_context *)_ctx;

	xml_encode_data(ctx->cmd, data, size);
	if (str_len(ctx->cmd) > SOLR_CMDBUF_SIZE-128) {
		solr_connection_post_more(ctx->post, str_data(ctx->cmd),
					  str_len(ctx->cmd));
		str_truncate(ctx->cmd, 0);
	}
	return 0;
}

static int fts_backend_solr_refresh(struct fts_backend *backend ATTR_UNUSED)
{
	return 0;
}

static int fts_backend_solr_optimize(struct fts_backend *backend ATTR_UNUSED)
{
	return 0;
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
		solr_quote_http(str, arg->value.str);
		str_append(str, "+OR+body:");
		solr_quote_http(str, arg->value.str);
		str_append(str, ")");
		break;
	}
	case SEARCH_BODY:
		if (arg->match_not)
			str_append_c(str, '-');
		str_append(str, "body:");
		solr_quote_http(str, arg->value.str);
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

static int
fts_backend_solr_lookup(struct fts_backend *_backend, struct mailbox *box,
			struct mail_search_arg *args,
			enum fts_lookup_flags flags,
			struct fts_result *result)
{
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_backend;
	bool and_args = (flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0;
	struct mail_namespace *ns;
	struct mailbox_status status;
	string_t *str;
	const char *box_name;
	pool_t pool;
	struct solr_result **results;
	int ret;

	fts_solr_set_default_ns(backend);
	mailbox_get_open_status(box, STATUS_UIDVALIDITY | STATUS_UIDNEXT,
				&status);

	str = t_str_new(256);
	str_printfa(str, "fl=uid,score&rows=%u&sort=uid+asc&q=%%7b!lucene+q.op%%3dAND%%7d",
		    status.uidnext);

	if (!solr_add_definite_query_args(str, args, and_args)) {
		/* can't search this query */
		return 0;
	}

	/* use a separate filter query for selecting the mailbox. it shouldn't
	   affect the score and there could be some caching benefits too. */
	str_append(str, "&fq=%2Buser:");
	solr_quote_http(str, box->storage->user->username);
	box_name = fts_box_get_root(box, &ns);
	str_printfa(str, "+%%2Buidv:%u+%%2Bbox:", status.uidvalidity);
	solr_quote_http(str, box_name);
	solr_add_ns_query_http(str, backend, ns);

	pool = pool_alloconly_create("fts solr search", 1024);
	ret = solr_connection_select(backend->solr_conn, str_c(str),
				     pool, &results);
	if (ret == 0 && results[0] != NULL) {
		if ((flags & FTS_LOOKUP_FLAG_NO_AUTO_FUZZY) == 0)
			array_append_array(&result->definite_uids, &results[0]->uids);
		else
			array_append_array(&result->maybe_uids, &results[0]->uids);
		array_append_array(&result->scores, &results[0]->scores);
	}
	result->scores_sorted = TRUE;
	pool_unref(&pool);
	return ret;
}

static char *
mailbox_get_id(struct solr_fts_backend *backend, struct mail_namespace *ns,
	       const char *mailbox, uint32_t uidvalidity)
{
	string_t *str = t_str_new(64);

	str_printfa(str, "%u\001", uidvalidity);
	str_append(str, mailbox);
	if (ns != backend->default_ns)
		str_printfa(str, "\001%s", ns->prefix);
	return str_c_modifiable(str);
}

static int
solr_search_multi(struct solr_fts_backend *backend, string_t *str,
		  struct mailbox *const boxes[],
		  enum fts_lookup_flags flags,
		  struct fts_multi_result *result)
{
	struct solr_result **solr_results;
	struct fts_result *fts_result;
	ARRAY(struct fts_result) fts_results;
	struct mail_namespace *ns;
	struct mailbox_status status;
	HASH_TABLE(char *, struct mailbox *) mailboxes;
	struct mailbox *box;
	const char *box_name;
	char *box_id;
	unsigned int i;
	size_t len;

	/* use a separate filter query for selecting the mailbox. it shouldn't
	   affect the score and there could be some caching benefits too. */
	str_append(str, "&fq=%2Buser:");
	if (backend->backend.ns->owner != NULL)
		solr_quote_http(str, backend->backend.ns->owner->username);
	else
		str_append(str, "%22%22");

	hash_table_create(&mailboxes, default_pool, 0, str_hash, strcmp);
	str_append(str, "%2B(");
	len = str_len(str);
	for (i = 0; boxes[i] != NULL; i++) {
		if (str_len(str) != len)
			str_append(str, "+OR+");

		box_name = fts_box_get_root(boxes[i], &ns);
		mailbox_get_open_status(boxes[i], STATUS_UIDVALIDITY, &status);
		str_printfa(str, "%%2B(%%2Buidv:%u+%%2Bbox:", status.uidvalidity);
		solr_quote_http(str, box_name);
		solr_add_ns_query_http(str, backend, ns);
		str_append_c(str, ')');

		box_id = mailbox_get_id(backend, ns, box_name, status.uidvalidity);
		hash_table_insert(mailboxes, box_id, boxes[i]);
	}
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
			i_warning("fts_solr: Lookup returned unexpected mailbox "
				  "with id=%s", solr_results[i]->box_id);
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
	result->box_results = array_front_modifiable(&fts_results);
	hash_table_destroy(&mailboxes);
	return 0;
}

static int
fts_backend_solr_lookup_multi(struct fts_backend *_backend,
			      struct mailbox *const boxes[],
			      struct mail_search_arg *args,
			      enum fts_lookup_flags flags,
			      struct fts_multi_result *result)
{
	bool and_args = (flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0;
	struct solr_fts_backend *backend =
		(struct solr_fts_backend *)_backend;
	string_t *str;

	fts_solr_set_default_ns(backend);

	str = t_str_new(256);
	str_printfa(str, "fl=ns,box,uidv,uid,score&rows=%u&sort=box+asc,uid+asc&q=%%7b!lucene+q.op%%3dAND%%7d",
		    SOLR_MAX_MULTI_ROWS);

	if (solr_add_definite_query_args(str, args, and_args)) {
		if (solr_search_multi(backend, str, boxes, flags, result) < 0)
			return -1;
	}
	/* FIXME: maybe_uids could be handled also with some more work.. */
	return 0;
}

struct fts_backend fts_backend_solr_old = {
	.name = "solr_old",
	.flags = 0,

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
		NULL,
		fts_backend_solr_optimize,
		fts_backend_default_can_lookup,
		fts_backend_solr_lookup,
		fts_backend_solr_lookup_multi,
		NULL
	}
};
