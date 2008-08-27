/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "solr-connection.h"
#include "fts-solr-plugin.h"

#include <curl/curl.h>

#define SOLR_CMDBUF_SIZE (1024*64)

struct solr_fts_backend_build_context {
	struct fts_backend_build_context ctx;

	struct solr_connection_post *post;
	uint32_t prev_uid, uid_validity;
	string_t *cmd;
	bool headers;
};

static struct solr_connection *solr_conn = NULL;

static void solr_quote_str(string_t *dest, const char *str)
{
	solr_connection_quote_str(solr_conn, dest, str);
}

static void
xml_encode_data(string_t *dest, const unsigned char *data, unsigned int len)
{
	unsigned int i;

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
		default:
			str_append_c(dest, data[i]);
			break;
		}
	}
}

static void xml_encode(string_t *dest, const char *str)
{
	xml_encode_data(dest, (const unsigned char *)str, strlen(str));
}

static struct fts_backend *
fts_backend_solr_init(struct mailbox *box ATTR_UNUSED)
{
	const struct fts_solr_settings *set = &fts_solr_settings;
	struct fts_backend *backend;

	if (solr_conn == NULL)
		solr_conn = solr_connection_init(set->url, set->debug);

	backend = i_new(struct fts_backend, 1);
	*backend = fts_backend_solr;

	if (set->substring_search)
		backend->flags |= FTS_BACKEND_FLAG_SUBSTRING_LOOKUPS;
	return backend;
}

static void fts_backend_solr_deinit(struct fts_backend *backend)
{
	i_free(backend);
}

static int fts_backend_solr_get_last_uid(struct fts_backend *backend,
					 uint32_t *last_uid_r)
{
	struct mailbox_status status;
	ARRAY_TYPE(seq_range) uids;
	const struct seq_range *uidvals;
	unsigned int count;
	string_t *str;

	str = t_str_new(256);
	str_append(str, "fl=uid&rows=1&sort=uid%20desc&q=");

	mailbox_get_status(backend->box, STATUS_UIDVALIDITY, &status);
	str_printfa(str, "uidv:%u%%20box:", status.uidvalidity);
	solr_quote_str(str, backend->box->name);
	str_append(str, "%20user:");
	solr_quote_str(str, backend->box->storage->ns->user->username);

	t_array_init(&uids, 1);
	if (solr_connection_select(solr_conn, str_c(str), &uids, NULL) < 0)
		return -1;

	uidvals = array_get(&uids, &count);
	if (count == 0) {
		/* nothing indexed yet for this mailbox */
		*last_uid_r = 0;
	} else if (count == 1 && uidvals[0].seq1 == uidvals[0].seq2) {
		*last_uid_r = uidvals[0].seq1;
	} else {
		i_error("fts_solr: Last UID lookup returned multiple rows");
		return -1;
	}
	return 0;
}

static int
fts_backend_solr_build_init(struct fts_backend *backend, uint32_t *last_uid_r,
			    struct fts_backend_build_context **ctx_r)
{
	struct solr_fts_backend_build_context *ctx;
	struct mailbox_status status;

	*last_uid_r = (uint32_t)-1;

	ctx = i_new(struct solr_fts_backend_build_context, 1);
	ctx->ctx.backend = backend;
	ctx->post = solr_connection_post_begin(solr_conn);
	ctx->cmd = str_new(default_pool, SOLR_CMDBUF_SIZE);

	mailbox_get_status(backend->box, STATUS_UIDVALIDITY, &status);
	ctx->uid_validity = status.uidvalidity;

	*ctx_r = &ctx->ctx;
	return 0;
}

static int
fts_backend_solr_build_more(struct fts_backend_build_context *_ctx,
			    uint32_t uid, const unsigned char *data,
			    size_t size, bool headers)
{
	struct solr_fts_backend_build_context *ctx =
		(struct solr_fts_backend_build_context *)_ctx;
	struct mailbox *box = _ctx->backend->box;
	string_t *cmd = ctx->cmd;

	/* body comes first, then headers */
	if (ctx->prev_uid != uid) {
		/* uid changed */
		if (ctx->prev_uid == 0)
			str_append(cmd, "<add>");
		else
			str_append(cmd, "</field></doc>");
		ctx->prev_uid = uid;

		str_printfa(cmd, "<doc>"
			    "<field name=\"uid\">%u</field>"
			    "<field name=\"uidv\">%u</field>",
			    uid, ctx->uid_validity);

		str_append(cmd, "<field name=\"box\">");
		xml_encode(cmd, box->name);
		str_append(cmd, "</field><field name=\"user\">");
		xml_encode(cmd, box->storage->ns->user->username);

		str_printfa(cmd, "</field><field name=\"id\">%u/%u/",
			    uid, ctx->uid_validity);
		xml_encode(cmd, box->storage->ns->user->username);
		str_append_c(cmd, '/');
		xml_encode(cmd, box->name);
		str_append(cmd, "</field>");

		ctx->headers = headers;
		if (headers) {
			str_append(cmd, "<field name=\"hdr\">");
		} else {
			str_append(cmd, "<field name=\"body\">");
		}
	} else if (headers && !ctx->headers) {
		str_append(cmd, "</field><field name=\"hdr\">");
	} else {
		i_assert(!(!headers && ctx->headers));
	}

	xml_encode_data(cmd, data, size);
	if (str_len(cmd) > SOLR_CMDBUF_SIZE-128) {
		solr_connection_post_more(ctx->post, str_data(cmd),
					  str_len(cmd));
		str_truncate(cmd, 0);
	}
	return 0;
}

static int
fts_backend_solr_build_deinit(struct fts_backend_build_context *_ctx)
{
	struct solr_fts_backend_build_context *ctx =
		(struct solr_fts_backend_build_context *)_ctx;
	int ret = 0;

	if (ctx->prev_uid != 0) {
		str_append(ctx->cmd, "</field></doc></add>");
		solr_connection_post_more(ctx->post, str_data(ctx->cmd),
					  str_len(ctx->cmd));
		ret = solr_connection_post_end(ctx->post);
		/* commit and wait until the documents we just indexed are
		   visible to the following search */
		if (solr_connection_post(solr_conn,
					 "<commit waitFlush=\"false\" "
					 "waitSearcher=\"true\"/>") < 0)
			ret = -1;
	}
	str_free(&ctx->cmd);
	i_free(ctx);
	return ret;
}

static void
fts_backend_solr_expunge(struct fts_backend *backend ATTR_UNUSED,
			 struct mail *mail)
{
	struct mailbox_status status;

	mailbox_get_status(mail->box, STATUS_UIDVALIDITY, &status);

	T_BEGIN {
		string_t *cmd;

		cmd = t_str_new(256);
		str_printfa(cmd, "<delete><id>%u/%u/",
			    mail->uid, status.uidvalidity);
		xml_encode(cmd, mail->box->storage->ns->user->username);
		str_append_c(cmd, '/');
		xml_encode(cmd, mail->box->name);
		str_append(cmd, "</id></delete>");

		(void)solr_connection_post(solr_conn, str_c(cmd));
	} T_END;
}

static void
fts_backend_solr_expunge_finish(struct fts_backend *backend ATTR_UNUSED,
				struct mailbox *box ATTR_UNUSED,
				bool committed ATTR_UNUSED)
{
	solr_connection_post(solr_conn,
		"<commit waitFlush=\"false\" waitSearcher=\"false\"/>");
}

static int fts_backend_solr_lock(struct fts_backend *backend ATTR_UNUSED)
{
	return 1;
}

static void fts_backend_solr_unlock(struct fts_backend *backend ATTR_UNUSED)
{
}

static int fts_backend_solr_lookup(struct fts_backend_lookup_context *ctx,
				   ARRAY_TYPE(seq_range) *definite_uids,
				   ARRAY_TYPE(seq_range) *maybe_uids,
				   ARRAY_TYPE(fts_score_map) *scores)
{
	struct mailbox *box = ctx->backend->box;
	const struct fts_backend_lookup_field *fields;
	unsigned int i, count;
	struct mailbox_status status;
	string_t *str;

	mailbox_get_status(box, STATUS_UIDVALIDITY, &status);

	str = t_str_new(256);
	str_printfa(str, "fl=uid,score&rows=%u&sort=uid%%20asc&q=",
		    status.uidnext);

	/* build a lucene search query from the fields */
	fields = array_get(&ctx->fields, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append(str, "%20");

		if ((fields[i].flags & FTS_LOOKUP_FLAG_INVERT) != 0)
			str_append_c(str, '-');

		if ((fields[i].flags & FTS_LOOKUP_FLAG_HEADER) == 0) {
			/* body only */
			i_assert((fields[i].flags & FTS_LOOKUP_FLAG_BODY) != 0);
			str_append(str, "body:");
		} else if ((fields[i].flags & FTS_LOOKUP_FLAG_BODY) == 0) {
			/* header only */
			str_append(str, "hdr:");
		} else {
			/* both */
			str_append(str, "any:");
		}
		solr_quote_str(str, fields[i].key);
	}

	/* use a separate filter query for selecting the mailbox. it shouldn't
	   affect the score and there could be some caching benefits too. */
	str_printfa(str, "&fq=uidv:%u%%20box:", status.uidvalidity);
	solr_quote_str(str, box->name);
	str_append(str, "%20user:");
	solr_quote_str(str, box->storage->ns->user->username);

	array_clear(maybe_uids);
	return solr_connection_select(solr_conn, str_c(str),
				      definite_uids, scores);
}

struct fts_backend fts_backend_solr = {
	MEMBER(name) "solr",
	MEMBER(flags) 0,

	{
		fts_backend_solr_init,
		fts_backend_solr_deinit,
		fts_backend_solr_get_last_uid,
		fts_backend_solr_build_init,
		fts_backend_solr_build_more,
		fts_backend_solr_build_deinit,
		fts_backend_solr_expunge,
		fts_backend_solr_expunge_finish,
		fts_backend_solr_lock,
		fts_backend_solr_unlock,
		NULL,
		NULL,
		fts_backend_solr_lookup
	}
};
