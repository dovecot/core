/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "module-context.h"
#include "iostream-ssl.h"
#include "http-url.h"
#include "http-client.h"
#include "settings.h"
#include "message-parser.h"
#include "mail-user.h"
#include "fts-parser.h"
#include "fts-user.h"

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
tika_get_http_client_url(struct fts_parser_context *parser_context, struct http_url **http_url_r)
{
	struct mail_user *user = parser_context->user;
	struct event *event = parser_context->event;
	const struct fts_settings *set = fts_user_get_settings(user);
	struct fts_parser_tika_user *tuser = TIKA_USER_CONTEXT(user);
	const char *url, *error;

	if (set->parsed_decoder_driver != FTS_DECODER_TIKA)
		return -1;

	url = set->decoder_tika_url;

	if (tuser != NULL) {
		*http_url_r = tuser->http_url;
		return *http_url_r == NULL ? -1 : 0;
	}

	tuser = p_new(user->pool, struct fts_parser_tika_user, 1);
	MODULE_CONTEXT_SET(user, fts_parser_tika_user_module, tuser);

	if (http_url_parse(url, NULL, HTTP_URL_ALLOW_USERINFO_PART, user->pool,
			   &tuser->http_url, &error) < 0) {
		e_error(event, "fts_tika: Failed to parse HTTP url %s: %s", url, error);
		return -1;
	}

	if (tika_http_client == NULL) {
		/* FIXME: We should initialize a shared client instead. However,
		          this is currently not possible due to an obscure bug
		          in the blocking HTTP payload API, which causes
		          conflicts with other HTTP applications like FTS Solr.
		          Using a private client will provide a quick fix for
		          now. */

		struct event *event_fts = event_create(user->event);
		settings_event_add_filter_name(event_fts, FTS_FILTER);
		struct event *event_tika = event_create(event_fts);
		settings_event_add_filter_name(event_tika, FTS_FILTER_DECODER_TIKA);
		int ret = http_client_init_private_auto(event, &tika_http_client, &error);
		event_unref(&event_tika);
		event_unref(&event_fts);
		if (ret < 0) {
			e_error(user->event, "%s", error);
			return -1;
		}
	}
	*http_url_r = tuser->http_url;
	return 0;
}

static void
fts_tika_parser_response(const struct http_response *response,
			 struct tika_fts_parser *parser)
{
	i_assert(parser->payload == NULL);
	struct event *event = parser->user->event;
	const struct fts_settings *set = fts_user_get_settings(parser->user);

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
			set->decoder_tika_url,
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
						set->decoder_tika_url,
						http_response_get_message(response));
			parser->payload = i_stream_create_from_data("", 0);
		} else {
			e_error(event, "fts_tika: PUT %s failed: %s",
				set->decoder_tika_url,
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

	if (tika_get_http_client_url(parser_context, &http_url) < 0)
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
	if (http_url->user != NULL) {
		http_client_request_set_auth_simple(
			http_req, http_url->user, http_url->password);
	}

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
	struct event *event = parser->user->event;
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
			e_error(event, "read(%s) failed: %s",
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
