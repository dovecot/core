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

