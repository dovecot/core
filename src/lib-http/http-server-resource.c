/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"

#include "http-url.h"
#include "http-server-private.h"

static struct event_category event_category_http_server_resource = {
	.name = "http-server-resource"
};

/*
 * Location
 */

static int
http_server_location_cmp(struct http_server_location *const *loc1,
			 struct http_server_location *const *loc2)
{
	return strcmp((*loc1)->path, (*loc2)->path);
}

static struct http_server_location *
http_server_location_add(struct http_server *server, pool_t pool,
			 const char *path)
{
	struct http_server_location qloc, *loc;
	unsigned int insert_idx;

	i_zero(&qloc);
	qloc.path = path;
	loc = &qloc;

	if (array_bsearch_insert_pos(&server->locations, &loc,
				     http_server_location_cmp, &insert_idx)) {
		struct http_server_location *const *loc_p;

		loc_p = array_idx(&server->locations, insert_idx);
		return *loc_p;
	}

	loc = p_new(pool, struct http_server_location, 1);
	loc->path = p_strdup(pool, path);
	array_insert(&server->locations, insert_idx, &loc, 1);
	return loc;
}

static int
http_server_location_find(struct http_server *server, const char *path,
			  struct http_server_location **loc_r,
			  const char **sub_path_r)
{
	struct http_server_location qloc, *loc;
	struct http_server_location *const *loc_p;
	size_t loc_len;
	unsigned int insert_idx;

	*sub_path_r = NULL;
	*loc_r = NULL;

	i_zero(&qloc);
	qloc.path = path;
	loc = &qloc;

	if (array_bsearch_insert_pos(&server->locations, &loc,
				     http_server_location_cmp, &insert_idx)) {
		/* Exact match */
		loc_p = array_idx(&server->locations, insert_idx);
		*sub_path_r = "";
		*loc_r = *loc_p;
		return 1;
	}
	if (insert_idx == 0) {
		/* Not found at all */
		return -1;
	}
	loc_p = array_idx(&server->locations, insert_idx-1);
	loc = *loc_p;

	loc_len = strlen(loc->path);
	if (!str_begins(path, loc->path)) {
		/* Location isn't a prefix of path */
		return -1;
	} else if (path[loc_len] != '/') {
		/* Match doesn't end at '/' */
		return -1;
	}

	*sub_path_r = &path[loc_len + 1];
	*loc_r = loc;
	return 0;
}

static void
http_server_location_remove(struct http_server *server,
			    struct http_server_location *loc)
{
	struct http_server_location *const *locp;

	array_foreach(&server->locations, locp) {
		if (*locp == loc) {
			array_delete(
				&server->locations,
				array_foreach_idx(&server->locations, locp), 1);
			return;
		}
	}
}

/*
 * Resource
 */

static void http_server_resource_update_event(struct http_server_resource *res)
{
	struct http_server_location *const *locs;
	unsigned int locs_count;

	locs = array_get(&res->locations, &locs_count);
	if (locs_count == 0) {
		event_set_append_log_prefix(res->event, "resource: ");
		return;
	}

	event_add_str(res->event, "path", locs[0]->path);
	event_set_append_log_prefix(
		res->event, t_strdup_printf("resource %s: ", locs[0]->path));
}

#undef http_server_resource_create
struct http_server_resource *
http_server_resource_create(struct http_server *server, pool_t pool,
			    http_server_resource_callback_t *callback,
			    void *context)
{
	struct http_server_resource *res;

	pool_ref(pool);

	pool = pool_alloconly_create("http server resource", 1024);
	res = p_new(pool, struct http_server_resource, 1);
	res->pool = pool;
	res->server = server;

	res->callback = callback;
	res->context = context;

	p_array_init(&res->locations, pool, 4);

	res->event = event_create(server->event);
	event_add_category(res->event, &event_category_http_server_resource);
	http_server_resource_update_event(res);

	array_append(&server->resources, &res, 1);

	return res;
}

void http_server_resource_free(struct http_server_resource **_res)
{
	struct http_server_resource *res = *_res;
	struct http_server_location *const *locp;

	if (res == NULL)
		return;

	*_res = NULL;

	e_debug(res->event, "Free");

	if (res->destroy_callback != NULL) {
		res->destroy_callback(res->destroy_context);
		res->destroy_callback = NULL;
	}

	array_foreach(&res->locations, locp)
		http_server_location_remove(res->server, *locp);

	event_unref(&res->event);
	pool_unref(&res->pool);
}

pool_t http_server_resource_get_pool(struct http_server_resource *res)
{
	return res->pool;
}

const char *http_server_resource_get_path(struct http_server_resource *res)
{
	struct http_server_location *const *locs;
	unsigned int locs_count;

	locs = array_get(&res->locations, &locs_count);
	i_assert(locs_count > 0);

	return locs[0]->path;
}

struct event *http_server_resource_get_event(struct http_server_resource *res)
{
	return res->event;
}

void http_server_resource_add_location(struct http_server_resource *res,
				       const char *path)
{
	struct http_server_location *loc;

	i_assert(*path == '\0' || *path == '/');

	loc = http_server_location_add(res->server, res->pool, path);
	i_assert(loc->resource == NULL);

	loc->resource = res;
	array_append(&res->locations, &loc, 1);

	if (array_count(&res->locations) == 1)
		http_server_resource_update_event(res);
}

int http_server_resource_find(struct http_server *server, const char *path,
			      struct http_server_resource **res_r,
			      const char **sub_path_r)
{
	struct http_server_location *loc;
	int ret;

	if (path == NULL)
		return -1;

	*res_r = NULL;
	*sub_path_r = NULL;

	ret = http_server_location_find(server, path, &loc, sub_path_r);
	if (ret < 0)
		return -1;

	i_assert(loc->resource != NULL);
	*res_r = loc->resource;
	return ret;
}

bool http_server_resource_callback(struct http_server_request *req)
{
	struct http_server *server = req->server;
	struct http_server_resource *res;
	const char *sub_path;

	switch (req->req.target.format) {
	case HTTP_REQUEST_TARGET_FORMAT_ORIGIN:
		/* According to RFC 7240, Section 5.3.1 only the origin form is
		   applicable to local resources on an origin server.
		*/
		break;
	case HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE:
	case HTTP_REQUEST_TARGET_FORMAT_AUTHORITY:
	case HTTP_REQUEST_TARGET_FORMAT_ASTERISK:
		/* Not applicable for a local resource. */
		return FALSE;
	}

	if (http_server_resource_find(server, req->req.target.url->path,
				      &res, &sub_path) < 0)
		return FALSE;

	e_debug(res->event, "Got request: %s", http_server_request_label(req));

	i_assert(res->callback != NULL);
	res->callback(res->context, req, sub_path);
	return TRUE;
}

#undef http_server_resource_set_destroy_callback
void http_server_resource_set_destroy_callback(struct http_server_resource *res,
					       void (*callback)(void *),
					       void *context)
{
	res->destroy_callback = callback;
	res->destroy_context = context;
}
