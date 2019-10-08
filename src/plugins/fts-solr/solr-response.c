/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "solr-response.h"

#include <expat.h>

enum solr_xml_response_state {
	SOLR_XML_RESPONSE_STATE_ROOT,
	SOLR_XML_RESPONSE_STATE_RESPONSE,
	SOLR_XML_RESPONSE_STATE_RESULT,
	SOLR_XML_RESPONSE_STATE_DOC,
	SOLR_XML_RESPONSE_STATE_CONTENT
};

enum solr_xml_content_state {
	SOLR_XML_CONTENT_STATE_NONE = 0,
	SOLR_XML_CONTENT_STATE_UID,
	SOLR_XML_CONTENT_STATE_SCORE,
	SOLR_XML_CONTENT_STATE_MAILBOX,
	SOLR_XML_CONTENT_STATE_NAMESPACE,
	SOLR_XML_CONTENT_STATE_UIDVALIDITY,
	SOLR_XML_CONTENT_STATE_ERROR
};

struct solr_lookup_xml_context {
	enum solr_xml_response_state state;
	enum solr_xml_content_state content_state;
	int depth;

	uint32_t uid, uidvalidity;
	float score;
	char *mailbox, *ns;

	pool_t result_pool;
	/* box_id -> solr_result */
	HASH_TABLE(char *, struct solr_result *) mailboxes;
	ARRAY(struct solr_result *) results;
};

static int
solr_xml_parse(struct solr_connection *conn,
	       const void *data, size_t size, bool done)
{
	enum XML_Error err;
	int line, col;

	if (conn->xml_failed)
		return -1;

	if (XML_Parse(conn->xml_parser, data, size, done ? 1 : 0) != 0)
		return 0;

	err = XML_GetErrorCode(conn->xml_parser);
	if (err != XML_ERROR_FINISHED) {
		line = XML_GetCurrentLineNumber(conn->xml_parser);
		col = XML_GetCurrentColumnNumber(conn->xml_parser);
		i_error("fts_solr: Invalid XML input at %d:%d: %s "
			"(near: %.*s)", line, col, XML_ErrorString(err),
			(int)I_MIN(size, 128), (const char *)data);
		conn->xml_failed = TRUE;
		return -1;
	}
	return 0;
}

static const char *attrs_get_name(const char **attrs)
{
	for (; *attrs != NULL; attrs += 2) {
		if (strcmp(attrs[0], "name") == 0)
			return attrs[1];
	}
	return "";
}

static void
solr_lookup_xml_start(void *context, const char *name, const char **attrs)
{
	struct solr_lookup_xml_context *ctx = context;
	const char *name_attr;

	i_assert(ctx->depth >= (int)ctx->state);

	ctx->depth++;
	if (ctx->depth - 1 > (int)ctx->state) {
		/* skipping over unwanted elements */
		return;
	}

	/* response -> result -> doc */
	switch (ctx->state) {
	case SOLR_XML_RESPONSE_STATE_ROOT:
		if (strcmp(name, "response") == 0)
			ctx->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_RESPONSE:
		if (strcmp(name, "result") == 0)
			ctx->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_RESULT:
		if (strcmp(name, "doc") == 0) {
			ctx->state++;
			ctx->uid = 0;
			ctx->score = 0;
			i_free_and_null(ctx->mailbox);
			i_free_and_null(ctx->ns);
			ctx->uidvalidity = 0;
		}
		break;
	case SOLR_XML_RESPONSE_STATE_DOC:
		name_attr = attrs_get_name(attrs);
		if (strcmp(name_attr, "uid") == 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_UID;
		else if (strcmp(name_attr, "score") == 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_SCORE;
		else if (strcmp(name_attr, "box") == 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_MAILBOX;
		else if (strcmp(name_attr, "ns") == 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_NAMESPACE;
		else if (strcmp(name_attr, "uidv") == 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_UIDVALIDITY;
		else
			break;
		ctx->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_CONTENT:
		break;
	}
}

static struct solr_result *
solr_result_get(struct solr_lookup_xml_context *ctx, const char *box_id)
{
	struct solr_result *result;
	char *box_id_dup;

	result = hash_table_lookup(ctx->mailboxes, box_id);
	if (result != NULL)
		return result;

	box_id_dup = p_strdup(ctx->result_pool, box_id);
	result = p_new(ctx->result_pool, struct solr_result, 1);
	result->box_id = box_id_dup;
	p_array_init(&result->uids, ctx->result_pool, 32);
	p_array_init(&result->scores, ctx->result_pool, 32);
	hash_table_insert(ctx->mailboxes, box_id_dup, result);
	array_push_back(&ctx->results, &result);
	return result;
}

static int solr_lookup_add_doc(struct solr_lookup_xml_context *ctx)
{
	struct fts_score_map *score;
	struct solr_result *result;
	const char *box_id;

	if (ctx->uid == 0) {
		i_error("fts_solr: uid missing from inside doc");
		return -1;
	}

	if (ctx->mailbox == NULL) {
		/* looking up from a single mailbox only */
		box_id = "";
	} else if (ctx->uidvalidity != 0) {
		/* old style lookup */
		string_t *str = t_str_new(64);
		str_printfa(str, "%u\001", ctx->uidvalidity);
		str_append(str, ctx->mailbox);
		if (ctx->ns != NULL)
			str_printfa(str, "\001%s", ctx->ns);
		box_id = str_c(str);
	} else {
		/* new style lookup */
		box_id = ctx->mailbox;
	}
	result = solr_result_get(ctx, box_id);

	if (seq_range_array_add(&result->uids, ctx->uid)) {
		/* duplicate result */
	} else if (ctx->score != 0) {
		score = array_append_space(&result->scores);
		score->uid = ctx->uid;
		score->score = ctx->score;
	}
	return 0;
}

static void solr_lookup_xml_end(void *context, const char *name ATTR_UNUSED)
{
	struct solr_lookup_xml_context *ctx = context;
	int ret;

	if (ctx->content_state == SOLR_XML_CONTENT_STATE_ERROR)
		return;

	i_assert(ctx->depth >= (int)ctx->state);

	if (ctx->state == SOLR_XML_RESPONSE_STATE_CONTENT &&
	    ctx->content_state == SOLR_XML_CONTENT_STATE_MAILBOX &&
	    ctx->mailbox == NULL) {
		/* mailbox is namespace prefix */
		ctx->mailbox = i_strdup("");
	}

	if (ctx->depth == (int)ctx->state) {
		ret = 0;
		if (ctx->state == SOLR_XML_RESPONSE_STATE_DOC) {
			T_BEGIN {
				ret = solr_lookup_add_doc(ctx);
			} T_END;
		}
		ctx->state--;
		if (ret < 0)
			ctx->content_state = SOLR_XML_CONTENT_STATE_ERROR;
		else
			ctx->content_state = SOLR_XML_CONTENT_STATE_NONE;
	}
	ctx->depth--;
}

static int uint32_parse(const char *str, int len, uint32_t *value_r)
{
	uint32_t value = 0;
	int i;

	for (i = 0; i < len; i++) {
		if (str[i] < '0' || str[i] > '9')
			break;
		value = value*10 + str[i]-'0';
	}
	if (i != len)
		return -1;

	*value_r = value;
	return 0;
}

static void solr_lookup_xml_data(void *context, const char *str, int len)
{
	struct solr_lookup_xml_context *ctx = context;
	char *new_name;

	switch (ctx->content_state) {
	case SOLR_XML_CONTENT_STATE_NONE:
		break;
	case SOLR_XML_CONTENT_STATE_UID:
		if (uint32_parse(str, len, &ctx->uid) < 0 || ctx->uid == 0) {
			i_error("fts_solr: received invalid uid '%s'",
				t_strndup(str, len));
			ctx->content_state = SOLR_XML_CONTENT_STATE_ERROR;
		}
		break;
	case SOLR_XML_CONTENT_STATE_SCORE:
		T_BEGIN {
			ctx->score = strtod(t_strndup(str, len), NULL);
		} T_END;
		break;
	case SOLR_XML_CONTENT_STATE_MAILBOX:
		/* this may be called multiple times, for example if input
		   contains '&' characters */
		new_name = ctx->mailbox == NULL ? i_strndup(str, len) :
			i_strconcat(ctx->mailbox, t_strndup(str, len), NULL);
		i_free(ctx->mailbox);
		ctx->mailbox = new_name;
		break;
	case SOLR_XML_CONTENT_STATE_NAMESPACE:
		new_name = ctx->ns == NULL ? i_strndup(str, len) :
			i_strconcat(ctx->ns, t_strndup(str, len), NULL);
		i_free(ctx->ns);
		ctx->ns = new_name;
		break;
	case SOLR_XML_CONTENT_STATE_UIDVALIDITY:
		if (uint32_parse(str, len, &ctx->uidvalidity) < 0)
			i_error("fts_solr: received invalid uidvalidity");
		break;
	case SOLR_XML_CONTENT_STATE_ERROR:
		break;
	}
}
