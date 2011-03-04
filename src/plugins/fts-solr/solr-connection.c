/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

/* curl: 7.16.0 curl_multi_timeout */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "solr-connection.h"

#include <curl/curl.h>
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
	SOLR_XML_CONTENT_STATE_UIDVALIDITY
};

struct solr_lookup_xml_context {
	enum solr_xml_response_state state;
	enum solr_xml_content_state content_state;
	int depth;

	uint32_t uid, uidvalidity;
	float score;
	char *mailbox, *ns;

	solr_uid_map_callback_t *callback;
	void *context;

	ARRAY_TYPE(seq_range) *uids;
	ARRAY_TYPE(fts_score_map) *scores;
};

struct solr_connection_post {
	struct solr_connection *conn;
	const unsigned char *data;
	size_t size, pos;
	char *url;

	unsigned int failed:1;
};

struct solr_connection {
	CURL *curl;
	CURLM *curlm;

	char curl_errorbuf[CURL_ERROR_SIZE];
	struct curl_slist *headers, *headers_post;
	XML_Parser xml_parser;

	char *url, *last_sent_url;
	char *http_failure;

	unsigned int debug:1;
	unsigned int posting:1;
	unsigned int xml_failed:1;
};

static size_t
curl_output_func(void *data, size_t element_size, size_t nmemb, void *context)
{
	struct solr_connection_post *post = context;
	size_t size = element_size * nmemb;

	/* @UNSAFE */
	if (size > post->size - post->pos)
		size = post->size - post->pos;

	memcpy(data, post->data + post->pos, size);
	post->pos += size;
	return size;
}

static int solr_xml_parse(struct solr_connection *conn,
			  const void *data, size_t size, bool done)
{
	enum XML_Error err;
	int line;

	if (conn->xml_failed)
		return -1;

	if (XML_Parse(conn->xml_parser, data, size, done))
		return 0;

	err = XML_GetErrorCode(conn->xml_parser);
	if (err != XML_ERROR_FINISHED) {
		line = XML_GetCurrentLineNumber(conn->xml_parser);
		i_error("fts_solr: Invalid XML input at line %d: %s",
			line, XML_ErrorString(err));
		conn->xml_failed = TRUE;
		return -1;
	}
	return 0;
}

static size_t
curl_input_func(void *data, size_t element_size, size_t nmemb, void *context)
{
	struct solr_connection *conn = context;
	size_t size = element_size * nmemb;

	(void)solr_xml_parse(conn, data, size, FALSE);
	return size;
}

static size_t
curl_header_func(void *data, size_t element_size, size_t nmemb, void *context)
{
	struct solr_connection *conn = context;
	size_t size = element_size * nmemb;
	const unsigned char *p;
	size_t i;

	if (conn->http_failure != NULL)
		return size;

	for (i = 0, p = data; i < size; i++) {
		if (p[i] == ' ') {
			i++;
			break;
		}
	}
	if (i == size || p[i] < '0' || p[i] > '9')
		i = 0;
	conn->http_failure = i_strndup(p + i, size - i);
	return size;
}

struct solr_connection *solr_connection_init(const char *url, bool debug)
{
	struct solr_connection *conn;

	conn = i_new(struct solr_connection, 1);
	conn->url = i_strdup(url);
	conn->debug = debug;

	conn->curlm = curl_multi_init();
	conn->curl = curl_easy_init();
	if (conn->curl == NULL || conn->curlm == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "fts_solr: Failed to allocate curl");
	}

	/* set global curl options */
	curl_easy_setopt(conn->curl, CURLOPT_ERRORBUFFER, conn->curl_errorbuf);
	if (conn->debug)
		curl_easy_setopt(conn->curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(conn->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(conn->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(conn->curl, CURLOPT_READFUNCTION, curl_output_func);
	curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, curl_input_func);
	curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, conn);
	curl_easy_setopt(conn->curl, CURLOPT_HEADERFUNCTION, curl_header_func);
	curl_easy_setopt(conn->curl, CURLOPT_HEADERDATA, conn);

	conn->headers = curl_slist_append(NULL, "Content-Type: text/xml");
	conn->headers_post = curl_slist_append(NULL, "Content-Type: text/xml");
	conn->headers_post = curl_slist_append(conn->headers_post,
					       "Transfer-Encoding: chunked");
	conn->headers_post = curl_slist_append(conn->headers_post,
					       "Expect:");
	curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, conn->headers);

	conn->xml_parser = XML_ParserCreate("UTF-8");
	if (conn->xml_parser == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "fts_solr: Failed to allocate XML parser");
	}
	return conn;
}

void solr_connection_deinit(struct solr_connection *conn)
{
	curl_slist_free_all(conn->headers);
	curl_slist_free_all(conn->headers_post);
	curl_multi_cleanup(conn->curlm);
	curl_easy_cleanup(conn->curl);
	i_free(conn->last_sent_url);
	i_free(conn->url);
	i_free(conn);
}

void solr_connection_http_escape(struct solr_connection *conn, string_t *dest,
				 const char *str)
{
	char *encoded;

	encoded = curl_easy_escape(conn->curl, str, 0);
	str_append(dest, encoded);
	curl_free(encoded);
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

static void solr_lookup_add_doc(struct solr_lookup_xml_context *ctx)
{
	struct fts_score_map *score;

	if (ctx->uid == 0) {
		i_error("fts_solr: Query didn't return uid");
		return;
	}

	if (ctx->callback != NULL) {
		if (ctx->mailbox == NULL) {
			i_error("fts_solr: Query didn't return mailbox");
			return;
		}
		if (!ctx->callback(ctx->ns, ctx->mailbox, ctx->uidvalidity,
				   &ctx->uid, ctx->context))
			return;
	}

	seq_range_array_add(ctx->uids, 0, ctx->uid);
	if (ctx->scores != NULL && ctx->score != 0) {
		score = array_append_space(ctx->scores);
		score->uid = ctx->uid;
		score->score = ctx->score;
	}
}

static void solr_lookup_xml_end(void *context, const char *name ATTR_UNUSED)
{
	struct solr_lookup_xml_context *ctx = context;

	i_assert(ctx->depth >= (int)ctx->state);

	if (ctx->depth == (int)ctx->state) {
		if (ctx->state == SOLR_XML_RESPONSE_STATE_DOC)
			solr_lookup_add_doc(ctx);
		ctx->state--;
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
		if (uint32_parse(str, len, &ctx->uid) < 0)
			i_error("fts_solr: received invalid uid");
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
	}
}

int solr_connection_select(struct solr_connection *conn, const char *query,
			   solr_uid_map_callback_t *callback, void *context,
			   ARRAY_TYPE(seq_range) *uids,
			   ARRAY_TYPE(fts_score_map) *scores)
{
	struct solr_lookup_xml_context solr_lookup_context;
	CURLcode ret;
	long httpret;

	i_assert(!conn->posting);

	memset(&solr_lookup_context, 0, sizeof(solr_lookup_context));
	solr_lookup_context.uids = uids;
	solr_lookup_context.scores = scores;
	solr_lookup_context.callback = callback;
	solr_lookup_context.context = context;

	i_free_and_null(conn->http_failure);
	conn->xml_failed = FALSE;
	XML_ParserReset(conn->xml_parser, "UTF-8");
	XML_SetElementHandler(conn->xml_parser,
			      solr_lookup_xml_start, solr_lookup_xml_end);
	XML_SetCharacterDataHandler(conn->xml_parser, solr_lookup_xml_data);
	XML_SetUserData(conn->xml_parser, &solr_lookup_context);

	/* curl v7.16 and older don't strdup() the URL */
	i_free(conn->last_sent_url);
	conn->last_sent_url = i_strconcat(conn->url, "select?", query, NULL);

	curl_easy_setopt(conn->curl, CURLOPT_URL, conn->last_sent_url);
	ret = curl_easy_perform(conn->curl);
	if (ret != 0) {
		i_error("fts_solr: HTTP GET failed: %s",
			conn->curl_errorbuf);
		return -1;
	}
	curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &httpret);
	if (httpret != 200) {
		i_error("fts_solr: Lookup failed: %s", conn->http_failure);
		return -1;
	}
	return solr_xml_parse(conn, NULL, 0, TRUE);
}

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn)
{
	struct solr_connection_post *post;
	CURLMcode merr;

	post = i_new(struct solr_connection_post, 1);
	post->conn = conn;

	i_assert(!conn->posting);
	conn->posting = TRUE;

	i_free_and_null(conn->http_failure);

	curl_easy_setopt(conn->curl, CURLOPT_READDATA, post);
	merr = curl_multi_add_handle(conn->curlm, conn->curl);
	if (merr != CURLM_OK) {
		i_error("fts_solr: curl_multi_add_handle() failed: %s",
			curl_multi_strerror(merr));
		post->failed = TRUE;
	} else {
		/* curl v7.16 and older don't strdup() the URL */
		post->url = i_strconcat(conn->url, "update", NULL);
		curl_easy_setopt(conn->curl, CURLOPT_URL, post->url);
		curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER,
				 conn->headers_post);
		curl_easy_setopt(conn->curl, CURLOPT_POST, (long)1);
		XML_ParserReset(conn->xml_parser, "UTF-8");
	}
	return post;
}

void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size)
{
	fd_set fdread;
	fd_set fdwrite;
	fd_set fdexcep;
	struct timeval timeout_tv;
	long timeout;
	CURLMsg *msg;
	CURLMcode merr;
	int ret, handles, maxfd, n;

	i_assert(post->conn->posting);

	if (post->failed)
		return;

	post->data = data;
	post->size = size;
	post->pos = 0;

	for (;;) {
		merr = curl_multi_perform(post->conn->curlm, &handles);
		if (merr == CURLM_CALL_MULTI_PERFORM)
			continue;
		if (merr != CURLM_OK) {
			i_error("fts_solr: curl_multi_perform() failed: %s",
				curl_multi_strerror(merr));
			break;
		}
		if ((post->pos == post->size && post->size != 0) ||
		    (handles == 0 && post->size == 0)) {
			/* everything sent successfully */
			return;
		}
		msg = curl_multi_info_read(post->conn->curlm, &n);
		if (msg != NULL && msg->msg == CURLMSG_DONE &&
		    msg->data.result != CURLE_OK) {
			i_error("fts_solr: curl post failed: %s",
				curl_easy_strerror(msg->data.result));
			break;
		}

		/* everything wasn't sent - wait. just use select,
		   since libcurl interface is easiest with it. */
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdexcep);

		merr = curl_multi_fdset(post->conn->curlm, &fdread, &fdwrite,
					&fdexcep, &maxfd);
		if (merr != CURLM_OK) {
			i_error("fts_solr: curl_multi_fdset() failed: %s",
				curl_multi_strerror(merr));
			break;
		}
		i_assert(maxfd >= 0);

		merr = curl_multi_timeout(post->conn->curlm, &timeout);
		if (merr != CURLM_OK) {
			i_error("fts_solr: curl_multi_timeout() failed: %s",
				curl_multi_strerror(merr));
			break;
		}

		if (timeout < 0) {
			timeout_tv.tv_sec = 1;
			timeout_tv.tv_usec = 0;
		} else {
			timeout_tv.tv_sec = timeout / 1000;
			timeout_tv.tv_usec = (timeout % 1000) * 1000;
		}
		ret = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout_tv);
		if (ret < 0) {
			i_error("fts_solr: select() failed: %m");
			break;
		}
	}
	post->failed = TRUE;
}

int solr_connection_post_end(struct solr_connection_post *post)
{
	struct solr_connection *conn = post->conn;
	long httpret;
	int ret = post->failed ? -1 : 0;

	i_assert(conn->posting);

	solr_connection_post_more(post, NULL, 0);

	curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &httpret);
	if (httpret != 200 && ret == 0) {
		i_error("fts_solr: Indexing failed: %s", conn->http_failure);
		ret = -1;
	}

	curl_easy_setopt(conn->curl, CURLOPT_READDATA, NULL);
	curl_easy_setopt(conn->curl, CURLOPT_POST, (long)0);
	curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, conn->headers);

	(void)curl_multi_remove_handle(conn->curlm, conn->curl);
	i_free(post->url);
	i_free(post);

	conn->posting = FALSE;
	return ret;
}

int solr_connection_post(struct solr_connection *conn, const char *cmd)
{
	struct solr_connection_post *post;

	post = solr_connection_post_begin(conn);
	solr_connection_post_more(post, (const unsigned char *)cmd,
				  strlen(cmd));
	return solr_connection_post_end(post);
}
