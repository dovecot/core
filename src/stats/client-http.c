/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "str.h"
#include "array.h"
#include "strescape.h"
#include "connection.h"
#include "ostream.h"
#include "master-service.h"
#include "http-server.h"
#include "http-url.h"
#include "stats-metrics.h"
#include "stats-service.h"
#include "client-http.h"

struct stats_http_client;

struct stats_http_client {
	struct http_server_connection *http_conn;
};

struct stats_http_resource {
	pool_t pool;
	const char *title;
	struct http_server_resource *resource;

	stats_http_resource_callback_t *callback;
	void *context;
};

static struct http_server *stats_http_server;
static ARRAY(struct stats_http_resource *) stats_http_resources;

/*
 * Request
 */

static void
stats_http_server_handle_request(void *context ATTR_UNUSED,
				 struct http_server_request *http_sreq)
{
	http_server_request_fail(http_sreq, 404, "Path Not Found");
}

/*
 * Connection
 */

static void
stats_http_server_connection_destroy(void *context, const char *reason);

static const struct http_server_callbacks stats_http_callbacks = {
        .connection_destroy = stats_http_server_connection_destroy,
        .handle_request = stats_http_server_handle_request
};

void client_http_create(struct master_service_connection *conn)
{
	struct stats_http_client *client;

	client = i_new(struct stats_http_client, 1);

	client->http_conn = http_server_connection_create(
		stats_http_server, conn->fd, conn->fd, conn->ssl,
		&stats_http_callbacks, client);
}

static void stats_http_client_destroy(struct stats_http_client *client)
{
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

static void
stats_http_server_connection_destroy(void *context,
				     const char *reason ATTR_UNUSED)
{
	struct stats_http_client *client = context;

	if (client->http_conn == NULL) {
		/* Already destroying client directly */
		return;
	}

	/* HTTP connection is destroyed already now */
	client->http_conn = NULL;

	/* Destroy the connection itself */
	stats_http_client_destroy(client);
}

/*
 * Resources
 */

/* Registry */

static void
stats_http_resource_callback(struct stats_http_resource *res,
			     struct http_server_request *req,
			     const char *sub_path)
{
	res->callback(res->context, req, sub_path);
}

#undef stats_http_resource_add
void stats_http_resource_add(const char *path, const char *title,
			     stats_http_resource_callback_t *callback,
			     void *context)
{
	struct stats_http_resource *res;
	pool_t pool;

	pool = pool_alloconly_create("stats http resource", 2048);
	res = p_new(pool, struct stats_http_resource, 1);
	res->pool = pool;
	res->title = p_strdup(pool, title);
	res->callback = callback;
	res->context = context;

	res->resource = http_server_resource_create(
		stats_http_server, pool, stats_http_resource_callback, res);
	http_server_resource_add_location(res->resource, path);

	pool_unref(&pool);
	array_append(&stats_http_resources, &res, 1);
}

/* Root */

static void
stats_http_resource_root_make_response(struct http_server_response *resp,
				       const struct http_request *hreq)
{
	struct stats_http_resource *const *res_p;
	struct http_url url;
	string_t *msg;

	http_url_init_authority_from(&url, hreq->target.url);

	msg = t_str_new(1024);

	str_append(msg, "<!DOCTYPE html>\n");
	str_append(msg, "<html lang=\"en\">\n");
	str_append(msg, "\n");
	str_append(msg, "<head>\n");
	str_append(msg, "<meta charset=\"utf-8\">\n");
	str_append(msg, "<title>Dovecot Stats</title>\n");
	str_append(msg, "</head>\n");
	str_append(msg, "\n");
	str_append(msg, "<body>\n");

	str_append(msg, "<h1>Dovecot Stats:</h1>\n");
	str_append(msg, "<p><ul>\n");

	array_foreach(&stats_http_resources, res_p) {
		struct stats_http_resource *res = *res_p;

		if (res->title == NULL)
			continue;

		/* List the resource at its primary location. */
		url.path = http_server_resource_get_path(res->resource);

		str_append(msg, "<li><a href=\"");
		str_append(msg, http_url_create(&url));
		str_append(msg, "\">");
		str_append(msg, res->title);
		str_append(msg, "</a></li>\n");
	}

	str_append(msg, "</ul></p>\n");
	str_append(msg, "</body>\n");
	str_append(msg, "\n");
	str_append(msg, "</html>\n");

	http_server_response_set_payload_data(
		resp, str_data(msg), str_len(msg));
}

static void
stats_http_resource_root_request(void *context ATTR_UNUSED,
				 struct http_server_request *req,
				 const char *sub_path)
{
	const struct http_request *hreq = http_server_request_get(req);
	struct http_server_response *resp;

	if (strcmp(hreq->method, "OPTIONS") == 0) {
		resp = http_server_response_create(req, 200, "OK");
		http_server_response_add_header(resp, "Allow", "GET");
		http_server_response_submit(resp);
		return;
	}
	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail_bad_method(req, "GET");
		return;
	}
	if (*sub_path != '\0') {
		http_server_request_fail(req, 404, "Not Found");
		return;
	}

	resp = http_server_response_create(req, 200, "OK");
	http_server_response_add_header(resp, "Content-Type",
					"text/html; charset=utf-8");

	stats_http_resource_root_make_response(resp, hreq);

	http_server_response_submit(resp);
}

/*
 * Server
 */

void client_http_init(const struct stats_settings *set)
{
	struct http_server_settings http_set = {
		.rawlog_dir = set->stats_http_rawlog_dir,
	};

	i_array_init(&stats_http_resources, 8);

	stats_http_server = http_server_init(&http_set);
	stats_http_resource_add("/", NULL,
				stats_http_resource_root_request, NULL);
}

void client_http_deinit(void)
{
	http_server_deinit(&stats_http_server);
	array_free(&stats_http_resources);
}
