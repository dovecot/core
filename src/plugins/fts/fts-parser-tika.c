/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "module-context.h"
#include "iostream-ssl.h"
#include "http-url.h"
#include "http-client.h"
#include "message-parser.h"
#include "mail-user.h"
#include "fts-parser.h"

#define TIKA_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_parser_tika_user_module)

struct fts_parser_tika_user {
	union mail_user_module_context module_ctx;
	struct http_url *http_url;
};

struct tika_fts_parser {
	struct fts_parser parser;
	struct mail_user *user;
	struct http_client_request *http_req;

	struct ioloop *ioloop;
	struct io *io;
	struct istream *payload;

	bool failed;
};

static struct http_client *tika_http_client = NULL;
static MODULE_CONTEXT_DEFINE_INIT(fts_parser_tika_user_module,
				  &mail_user_module_register);

static int
tika_get_http_client_url(struct mail_user *user, struct http_url **http_url_r)
{
	struct fts_parser_tika_user *tuser = TIKA_USER_CONTEXT(user);
	struct http_client_settings http_set;
	struct ssl_iostream_settings ssl_set;
	const char *url, *error;

	url = mail_user_plugin_getenv(user, "fts_tika");
	if (url == NULL) {
		/* fts_tika disabled */
		return -1;
	}

	if (tuser != NULL) {
		*http_url_r = tuser->http_url;
		return *http_url_r == NULL ? -1 : 0;
	}

	tuser = p_new(user->pool, struct fts_parser_tika_user, 1);
	MODULE_CONTEXT_SET(user, fts_parser_tika_user_module, tuser);

	if (http_url_parse(url, NULL, 0, user->pool,
			   &tuser->http_url, &error) < 0) {
		i_error("fts_tika: Failed to parse HTTP url %s: %s", url, error);
		return -1;
	}

	if (tika_http_client == NULL) {
		i_zero(&ssl_set);
		mail_user_init_ssl_client_settings(user, &ssl_set);

		i_zero(&http_set);
		http_set.max_idle_time_msecs = 100;
		http_set.max_parallel_connections = 1;
		http_set.max_pipelined_requests = 1;
		http_set.max_redirects = 1;
		http_set.max_attempts = 3;
		http_set.connect_timeout_msecs = 5*1000;
		http_set.request_timeout_msecs = 60*1000;
		http_set.ssl = &ssl_set;
		http_set.debug = user->mail_debug;
		tika_http_client = http_client_init(&http_set);
	}
	*http_url_r = tuser->http_url;
	return 0;
}

static void
fts_tika_parser_response(const struct http_response *response,
			 struct tika_fts_parser *parser)
{
	i_assert(parser->payload == NULL);

	switch (response->status) {
	case 200:
		/* read response */
		if (response->payload == NULL)
			parser->payload = i_stream_create_from_data("", 0);
		else {
			i_stream_ref(response->payload);
			parser->payload = response->payload;
		}
		break;
	case 204: /* empty response */
	case 415: /* Unsupported Media Type */
	case 422: /* Unprocessable Entity */
		e_debug(parser->user->event, "fts_tika: PUT %s failed: %s",
			mail_user_plugin_getenv(parser->user, "fts_tika"),
			http_response_get_message(response));
		parser->payload = i_stream_create_from_data("", 0);
		break;
	default:
		if (response->status / 100 == 5) {
			/* Server Error - the problem could be anything (in Tika or
			   HTTP server or proxy) and might be retriable, but Tika has
			   trouble processing some documents and throws up this error
			   every time for those documents. */
			parser->parser.may_need_retry = TRUE;
			i_free(parser->parser.retriable_error_msg);
			parser->parser.retriable_error_msg =
				i_strdup_printf("fts_tika: PUT %s failed: %s",
						mail_user_plugin_getenv(parser->user, "fts_tika"),
						http_response_get_message(response));
			parser->payload = i_stream_create_from_data("", 0);
		} else {
			i_error("fts_tika: PUT %s failed: %s",
				mail_user_plugin_getenv(parser->user, "fts_tika"),
				http_response_get_message(response));
			parser->failed = TRUE;
		}
		break;
	}
	parser->http_req = NULL;
	io_loop_stop(current_ioloop);
}

static struct fts_parser *
fts_parser_tika_try_init(struct fts_parser_context *parser_context)
{
	struct tika_fts_parser *parser;
	struct http_url *http_url;
	struct http_client_request *http_req;

	if (tika_get_http_client_url(parser_context->user, &http_url) < 0)
		return NULL;
	if (http_url->path == NULL)
		http_url->path = "/";

	parser = i_new(struct tika_fts_parser, 1);
	parser->parser.v = fts_parser_tika;
	parser->user = parser_context->user;

	http_req = http_client_request(tika_http_client, "PUT",
			http_url->host.name,
			t_strconcat(http_url->path, http_url->enc_query, NULL),
			fts_tika_parser_response, parser);
	http_client_request_set_port(http_req, http_url->port);
	http_client_request_set_ssl(http_req, http_url->have_ssl);
	if (parser_context->content_type != NULL)
		http_client_request_add_header(http_req, "Content-Type",
					       parser_context->content_type);
	if (parser_context->content_disposition != NULL)
		http_client_request_add_header(http_req, "Content-Disposition",
					       parser_context->content_disposition);
	http_client_request_add_header(http_req, "Accept", "text/plain");

	parser->http_req = http_req;
	return &parser->parser;
}

static void fts_parser_tika_more(struct fts_parser *_parser,
				 struct message_block *block)
{
	struct tika_fts_parser *parser = (struct tika_fts_parser *)_parser;
	struct ioloop *prev_ioloop = current_ioloop;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	if (block->size > 0) {
		/* first we'll send everything to Tika */
		if (!parser->failed &&
		    http_client_request_send_payload(&parser->http_req,
						     block->data,
						     block->size) < 0)
			parser->failed = TRUE;
		block->size = 0;
		return;
	}

	if (parser->payload == NULL) {
		/* read the result from Tika */
		if (!parser->failed &&
		    http_client_request_finish_payload(&parser->http_req) < 0)
			parser->failed = TRUE;
		if (!parser->failed && parser->payload == NULL)
			http_client_wait(tika_http_client);
		if (parser->failed)
			return;
		i_assert(parser->payload != NULL);
	}
	/* continue returning data from Tika. we'll create a new ioloop just
	   for reading this one payload. */
	while ((ret = i_stream_read_more(parser->payload, &data, &size)) == 0) {
		if (parser->failed)
			break;
		/* wait for more input from Tika */
		if (parser->ioloop == NULL) {
			parser->ioloop = io_loop_create();
			parser->io = io_add_istream(parser->payload, io_loop_stop,
						    current_ioloop);
		} else {
			io_loop_set_current(parser->ioloop);
		}
		io_loop_run(current_ioloop);
	}
	/* switch back to original ioloop. */
	io_loop_set_current(prev_ioloop);

	if (parser->failed)
		;
	else if (size > 0) {
		i_assert(ret > 0);
		block->data = data;
		block->size = size;
		i_stream_skip(parser->payload, size);
	} else {
		/* finished */
		i_assert(ret == -1);
		if (parser->payload->stream_errno != 0) {
			i_error("read(%s) failed: %s",
				i_stream_get_name(parser->payload),
				i_stream_get_error(parser->payload));
			parser->failed = TRUE;
		}
	}
}

static int fts_parser_tika_deinit(struct fts_parser *_parser, const char **retriable_err_msg_r)
{
	struct tika_fts_parser *parser = (struct tika_fts_parser *)_parser;
	int ret = _parser->may_need_retry ? 0: (parser->failed ? -1 : 1);

	i_assert(ret != 0 || _parser->retriable_error_msg != NULL);
	if (retriable_err_msg_r != NULL)
		*retriable_err_msg_r = t_strdup(_parser->retriable_error_msg);
	i_free(_parser->retriable_error_msg);

	/* remove io before unrefing payload - otherwise lib-http adds another
	   timeout to ioloop unnecessarily */
	i_stream_unref(&parser->payload);
	io_remove(&parser->io);
	http_client_request_abort(&parser->http_req);
	if (parser->ioloop != NULL) {
		io_loop_set_current(parser->ioloop);
		io_loop_destroy(&parser->ioloop);
	}
	i_free(parser);
	return ret;
}

static void fts_parser_tika_unload(void)
{
	if (tika_http_client != NULL)
		http_client_deinit(&tika_http_client);
}

struct fts_parser_vfuncs fts_parser_tika = {
	fts_parser_tika_try_init,
	fts_parser_tika_more,
	fts_parser_tika_deinit,
	fts_parser_tika_unload
};
