/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "event-exporter.h"
#include "settings.h"
#include "http-client.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "stats-common.h"

struct http_post_event_exporter {
	struct event_exporter exporter;
	const struct event_exporter_http_post_settings *set;
	struct http_client *client;
};

struct event_exporter_http_post_settings {
	pool_t pool;

	const char *event_exporter_http_post_url;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct event_exporter_http_post_settings)

static const struct setting_define event_exporter_http_post_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "event_exporter_http_post", },
	DEF(STR, event_exporter_http_post_url),

	SETTING_DEFINE_LIST_END
};

static const struct event_exporter_http_post_settings event_exporter_http_post_default_settings = {
	.event_exporter_http_post_url = "",
};

static const struct setting_keyvalue event_exporter_http_post_default_settings_keyvalue[] = {
	{ "event_exporter_http_post/http_client_request_absolute_timeout", "250ms" },
	{ NULL, NULL }
};

const struct setting_parser_info event_exporter_http_post_setting_parser_info = {
	.name = "event_exporter_http_post",

	.defines = event_exporter_http_post_setting_defines,
	.defaults = &event_exporter_http_post_default_settings,
	.default_settings = event_exporter_http_post_default_settings_keyvalue,

	.struct_size = sizeof(struct event_exporter_http_post_settings),
	.pool_offset1 = 1 + offsetof(struct event_exporter_http_post_settings, pool),
};

static int
event_exporter_http_post_init(pool_t pool, struct event *event,
			      struct event_exporter **exporter_r,
			      const char **error_r)
{
	struct http_post_event_exporter *exporter =
		p_new(pool, struct http_post_event_exporter, 1);
	if (settings_get(event, &event_exporter_http_post_setting_parser_info,
			 0, &exporter->set, error_r) < 0)
		return -1;
	if (http_client_init_auto(event, &exporter->client, error_r) < 0)
		return -1;
	*exporter_r = &exporter->exporter;
	return 0;
}

static void
event_exporter_http_post_deinit(struct event_exporter *_exporter)
{
	struct http_post_event_exporter *exporter =
		container_of(_exporter, struct http_post_event_exporter,
			     exporter);

	http_client_deinit(&exporter->client);
	settings_free(exporter->set);
}

static void response_fxn(const struct http_response *response,
			 void *context ATTR_UNUSED)
{
	static time_t last_log;
	static unsigned int suppressed;

	if (http_response_is_success(response))
		return;

	if (last_log == ioloop_time) {
		suppressed++;
		return; /* don't spam the log */
	}

	if (suppressed == 0)
		i_error("Failed to export event via HTTP POST: %d %s",
			response->status, response->reason);
	else
		i_error("Failed to export event via HTTP POST: %d %s (%u more errors suppressed)",
			response->status, response->reason, suppressed);

	last_log = ioloop_time;
	suppressed = 0;
}

static void
event_exporter_http_post_send(struct event_exporter *_exporter,
			      const buffer_t *buf)
{
	struct http_post_event_exporter *exporter =
		container_of(_exporter, struct http_post_event_exporter,
			     exporter);
	struct http_client_request *req;

	req = http_client_request_url_str(exporter->client, "POST",
		exporter->set->event_exporter_http_post_url,
		response_fxn, NULL);
	http_client_request_add_header(req, "Content-Type", _exporter->format_mime_type);
	http_client_request_set_payload_data(req, buf->data, buf->used);

	http_client_request_submit(req);
}

const struct event_exporter_transport event_exporter_transport_http_post = {
	.name = "http-post",

	.init = event_exporter_http_post_init,
	.deinit = event_exporter_http_post_deinit,
	.send = event_exporter_http_post_send,
};
