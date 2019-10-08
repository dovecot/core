/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "istream.h"
#include "http-url.h"
#include "http-client.h"
#include "fts-solr-plugin.h"
#include "solr-connection.h"

#include <expat.h>

struct solr_connection_post {
	struct solr_connection *conn;

	struct http_client_request *http_req;

	bool failed:1;
};

struct solr_connection {
	XML_Parser xml_parser;

	char *http_host;
	in_port_t http_port;
	char *http_base_url;
	char *http_failure;
	char *http_user;
	char *http_password;

	int request_status;

	struct istream *payload;
	struct io *io;

	bool debug:1;
	bool posting:1;
	bool xml_failed:1;
	bool http_ssl:1;
};

#include "solr-response.c"

/* Regardless of the specified URL, make sure path ends in '/' */
static char *solr_connection_create_http_base_url(struct http_url *http_url)
{
	if (http_url->path == NULL)
		return i_strconcat("/", http_url->enc_query, NULL);
	size_t len = strlen(http_url->path);
	if (len > 0 && http_url->path[len-1] != '/')
		return i_strconcat(http_url->path, "/",
				   http_url->enc_query, NULL);
	/* http_url->path is NULL on empty path, so this is impossible. */
	i_assert(len != 0);
	return i_strconcat(http_url->path, http_url->enc_query, NULL);
}

int solr_connection_init(const struct fts_solr_settings *solr_set,
			 const struct ssl_iostream_settings *ssl_client_set,
			 struct solr_connection **conn_r, const char **error_r)
{
	struct http_client_settings http_set;
	struct solr_connection *conn;
	struct http_url *http_url;
	const char *error;

	if (http_url_parse(solr_set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
			   pool_datastack_create(), &http_url, &error) < 0) {
		*error_r = t_strdup_printf(
			"fts_solr: Failed to parse HTTP url: %s", error);
		return -1;
	}

	conn = i_new(struct solr_connection, 1);
	conn->http_host = i_strdup(http_url->host.name);
	conn->http_port = http_url->port;
	conn->http_base_url = solr_connection_create_http_base_url(http_url);
	conn->http_ssl = http_url->have_ssl;
	if (http_url->user != NULL) {
		conn->http_user = i_strdup(http_url->user);
		/* allow empty password */
		conn->http_password = i_strdup(http_url->password != NULL ?
					       http_url->password : "");
	}

	conn->debug = solr_set->debug;

	if (solr_http_client == NULL) {
		i_zero(&http_set);
		http_set.max_idle_time_msecs = 5*1000;
		http_set.max_parallel_connections = 1;
		http_set.max_pipelined_requests = 1;
		http_set.max_redirects = 1;
		http_set.max_attempts = 3;
		http_set.connect_timeout_msecs = 5*1000;
		http_set.request_timeout_msecs = 60*1000;
		http_set.ssl = ssl_client_set;
		http_set.debug = solr_set->debug;
		http_set.rawlog_dir = solr_set->rawlog_dir;
		solr_http_client = http_client_init(&http_set);
	}

	conn->xml_parser = XML_ParserCreate("UTF-8");
	if (conn->xml_parser == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "fts_solr: Failed to allocate XML parser");
	}
	*conn_r = conn;
	return 0;
}

void solr_connection_deinit(struct solr_connection **_conn)
{
	struct solr_connection *conn = *_conn;

	*_conn = NULL;
	XML_ParserFree(conn->xml_parser);
	i_free(conn->http_host);
	i_free(conn->http_base_url);
	i_free(conn->http_user);
	i_free(conn->http_password);
	i_free(conn);
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

static void solr_connection_payload_input(struct solr_connection *conn)
{
	const unsigned char *data;
	size_t size;
	int ret;

	/* read payload */
	while ((ret = i_stream_read_more(conn->payload, &data, &size)) > 0) {
		(void)solr_xml_parse(conn, data, size, FALSE);
		i_stream_skip(conn->payload, size);
	}

	if (ret == 0) {
		/* we will be called again for more data */
	} else {
		if (conn->payload->stream_errno != 0) {
			i_error("fts_solr: "
				"failed to read payload from HTTP server: %m");
			conn->request_status = -1;
		}
		io_remove(&conn->io);
		i_stream_unref(&conn->payload);
	}
}

static void
solr_connection_select_response(const struct http_response *response,
				struct solr_connection *conn)
{
	if (response->status / 100 != 2) {
		i_error("fts_solr: Lookup failed: %s",
			http_response_get_message(response));
		conn->request_status = -1;
		return;
	}

	if (response->payload == NULL) {
		i_error("fts_solr: Lookup failed: Empty response payload");
		conn->request_status = -1;
		return;
	}

	i_stream_ref(response->payload);
	conn->payload = response->payload;
	conn->io = io_add_istream(response->payload,
				  solr_connection_payload_input, conn);
	solr_connection_payload_input(conn);
}

int solr_connection_select(struct solr_connection *conn, const char *query,
			   pool_t pool, struct solr_result ***box_results_r)
{
	struct solr_lookup_xml_context solr_lookup_context;
	struct http_client_request *http_req;
	const char *url;
	int parse_ret;

	i_zero(&solr_lookup_context);
	solr_lookup_context.result_pool = pool;
	hash_table_create(&solr_lookup_context.mailboxes, default_pool, 0,
			  str_hash, strcmp);
	p_array_init(&solr_lookup_context.results, pool, 32);

	i_free_and_null(conn->http_failure);
	conn->xml_failed = FALSE;
	XML_ParserReset(conn->xml_parser, "UTF-8");
	XML_SetElementHandler(conn->xml_parser,
			      solr_lookup_xml_start, solr_lookup_xml_end);
	XML_SetCharacterDataHandler(conn->xml_parser, solr_lookup_xml_data);
	XML_SetUserData(conn->xml_parser, &solr_lookup_context);

	url = t_strconcat(conn->http_base_url, "select?", query, NULL);

	http_req = http_client_request(solr_http_client, "GET",
				       conn->http_host, url,
				       solr_connection_select_response, conn);
	if (conn->http_user != NULL) {
		http_client_request_set_auth_simple(
			http_req, conn->http_user, conn->http_password);
	}
	http_client_request_set_port(http_req, conn->http_port);
	http_client_request_set_ssl(http_req, conn->http_ssl);
	http_client_request_submit(http_req);

	conn->request_status = 0;
	http_client_wait(solr_http_client);

	if (conn->request_status < 0 ||
	    solr_lookup_context.content_state == SOLR_XML_CONTENT_STATE_ERROR)
		return -1;

	parse_ret = solr_xml_parse(conn, "", 0, TRUE);
	hash_table_destroy(&solr_lookup_context.mailboxes);

	array_append_zero(&solr_lookup_context.results);
	*box_results_r = array_front_modifiable(&solr_lookup_context.results);
	return parse_ret;
}

static void
solr_connection_update_response(const struct http_response *response,
				struct solr_connection *conn)
{
	if (response->status / 100 != 2) {
		i_error("fts_solr: Indexing failed: %s",
			http_response_get_message(response));
		conn->request_status = -1;
	}
}

static struct http_client_request *
solr_connection_post_request(struct solr_connection *conn)
{
	struct http_client_request *http_req;
	const char *url;

	url = t_strconcat(conn->http_base_url, "update", NULL);

	http_req = http_client_request(solr_http_client, "POST",
				       conn->http_host, url,
				       solr_connection_update_response, conn);
	if (conn->http_user != NULL) {
		http_client_request_set_auth_simple(
			http_req, conn->http_user, conn->http_password);
	}
	http_client_request_set_port(http_req, conn->http_port);
	http_client_request_set_ssl(http_req, conn->http_ssl);
	http_client_request_add_header(http_req, "Content-Type", "text/xml");
	return http_req;
}

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn)
{
	struct solr_connection_post *post;

	i_assert(!conn->posting);
	conn->posting = TRUE;

	post = i_new(struct solr_connection_post, 1);
	post->conn = conn;
	post->http_req = solr_connection_post_request(conn);
	XML_ParserReset(conn->xml_parser, "UTF-8");
	return post;
}

void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size)
{
	struct solr_connection *conn = post->conn;
	i_assert(post->conn->posting);

	if (post->failed)
		return;

	if (conn->request_status == 0) {
		(void)http_client_request_send_payload(
			&post->http_req, data, size);
	}
	if (conn->request_status < 0)
		post->failed = TRUE;
}

int solr_connection_post_end(struct solr_connection_post **_post)
{
	struct solr_connection_post *post = *_post;
	struct solr_connection *conn = post->conn;
	int ret = post->failed ? -1 : 0;

	i_assert(conn->posting);

	*_post = NULL;

	if (!post->failed) {
		if (http_client_request_finish_payload(&post->http_req) < 0 ||
			conn->request_status < 0) {
			ret = -1;
		}
	} else {
		http_client_request_abort(&post->http_req);
	}
	i_free(post);

	conn->posting = FALSE;
	return ret;
}

int solr_connection_post(struct solr_connection *conn, const char *cmd)
{
	struct http_client_request *http_req;
	struct istream *post_payload;

	i_assert(!conn->posting);

	http_req = solr_connection_post_request(conn);
	post_payload = i_stream_create_from_data(cmd, strlen(cmd));
	http_client_request_set_payload(http_req, post_payload, TRUE);
	i_stream_unref(&post_payload);
	http_client_request_submit(http_req);

	XML_ParserReset(conn->xml_parser, "UTF-8");

	conn->request_status = 0;
	http_client_wait(solr_http_client);

	return conn->request_status;
}
