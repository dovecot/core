/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "dlua-script-private.h"
#include "http-url.h"
#include "http-client.h"
#include "http-client-private.h"
#include "istream.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"

#define DLUA_DOVECOT_HTTP "http"
#define DLUA_HTTP_CLIENT "struct http_client"
#define DLUA_HTTP_CLIENT_REQUEST "struct http_client_request"
#define DLUA_HTTP_RESPONSE "struct dlua_http_response"

struct dlua_http_response {
	unsigned char version_major;
	unsigned char version_minor;
	unsigned int status;
	const char *reason;
	const char *location;
	string_t *payload;
	time_t date, retry_after;
	ARRAY_TYPE(http_header_field) headers;
	pool_t pool;
	const char *error;
	struct event *event;
};

struct dlua_http_response_payload_context {
	struct io *io;
	struct istream *payload_istream;
	string_t *payload_str;
	char *error;
	struct event *event;
	pool_t pool;
};

static struct http_client_request *
dlua_check_http_request(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_HTTP_CLIENT_REQUEST,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct http_client_request **bp = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

static int dlua_http_request_gc(lua_State *L)
{
	struct http_client_request **req = lua_touserdata(L, 1);
	http_client_request_unref(req);
	return 0;
}

static int dlua_http_request_add_header(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);

	struct http_client_request *req = dlua_check_http_request(L, 1);

	const char *name = luaL_checkstring(L, 2);
	const char *value = luaL_checkstring(L, 3);
	http_client_request_add_header(req, name, value);
	return 0;
}

static int dlua_http_request_remove_header(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);

	struct http_client_request *req = dlua_check_http_request(L, 1);

	const char *name = luaL_checkstring(L, 2);
	http_client_request_remove_header(req, name);
	return 0;
}

static int dlua_http_request_set_payload(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);

	struct http_client_request *req = dlua_check_http_request(L, 1);
	struct istream *payload_istream;

	const char *payload = luaL_checkstring(L, 2);
	payload_istream = i_stream_create_copy_from_data(payload,
			strlen(payload));
	http_client_request_set_payload(req, payload_istream, TRUE);
	i_stream_unref(&payload_istream);
	return 0;
}

static int dlua_http_request_submit(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);

	struct http_client_request *req = dlua_check_http_request(L, 1);

	/* Clear the GC hook for this request. It will be freed after it's
	   submitted. */
	lua_getfield(L, -1, "item");
	if (lua_getmetatable(L, -1) != 1)
		return luaL_error(L, "Cound't get metatable for the request");
	lua_pushnil(L);
	lua_setfield(L, -2, "__gc");
	lua_pop(L, 2);

	http_client_request_submit(req);
	http_client_wait(req->client);
	return 1;
}

static luaL_Reg lua_dovecot_http_request_methods[] = {
	{ "add_header", dlua_http_request_add_header },
	{ "remove_header", dlua_http_request_remove_header },
	{ "set_payload", dlua_http_request_set_payload },
	{ "submit", dlua_http_request_submit },
	{ NULL, NULL }
};

static void dlua_push_http_request(lua_State *L, struct http_client_request *req)
{
	luaL_checkstack(L, 3, "out of memory");
	lua_createtable(L, 0, 1);
	luaL_setmetatable(L, DLUA_HTTP_CLIENT_REQUEST);

	/* we need to attach gc to userdata to support older lua*/
	struct http_client_request **ptr = lua_newuserdata(L, sizeof(struct http_client_request*));
	*ptr = req;
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, dlua_http_request_gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");

	luaL_setfuncs(L, lua_dovecot_http_request_methods, 0);
}


static struct http_client *dlua_check_http_client(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_HTTP_CLIENT,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct http_client **bp = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

static int dlua_http_client_gc(lua_State *L)
{
	struct http_client **_client = lua_touserdata(L, 1);
	http_client_deinit(_client);
	return 0;
}
static int dlua_http_resp_gc(lua_State *L)
{
	struct dlua_http_response **_resp = lua_touserdata(L, 1);
	array_free(&(*_resp)->headers);
	pool_unref(&(*_resp)->pool);
	return 0;
}

static struct dlua_http_response *dlua_check_http_response(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_HTTP_RESPONSE,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct dlua_http_response **bp = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

static int dlua_http_response_get_status(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);

	const struct dlua_http_response *resp = dlua_check_http_response(L, 1);
	lua_pushinteger(L, resp->status);
	return 1;
}

static int dlua_http_response_get_payload(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);

	const struct dlua_http_response *resp = dlua_check_http_response(L, 1);
	lua_pushlstring(L, resp->payload->data, resp->payload->used);
	return 1;
}

static int dlua_http_response_get_header(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);

	const struct dlua_http_response *resp = dlua_check_http_response(L, 1);
	const char *name = luaL_checkstring(L, 2);
	const char *value = "";

	const struct http_header_field *hfield;
	array_foreach(&resp->headers, hfield) {
		if (http_header_field_is(hfield, name)) {
			value = hfield->value;
			break;
		}
	}

	lua_pushstring(L, value);
	return 1;
}

static int dlua_http_response_get_reason(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);

	const struct dlua_http_response *resp = dlua_check_http_response(L, 1);
	lua_pushstring(L, resp->reason);
	return 1;
}

static const luaL_Reg dovecot_http_response_methods[] = {
	{ "status", dlua_http_response_get_status },
	{ "payload", dlua_http_response_get_payload },
	{ "header", dlua_http_response_get_header },
	{ "reason", dlua_http_response_get_reason },
	{ NULL, NULL }
};

static void
dlua_push_http_response(lua_State *L, const struct dlua_http_response *resp)
{
	luaL_checkstack(L, 3, "out of memory");
	lua_createtable(L, 0, 1);
	luaL_setmetatable(L, DLUA_HTTP_RESPONSE);

	/* we need to attach gc to userdata to support older lua*/
	const struct dlua_http_response **ptr = lua_newuserdata(L, sizeof(struct dlua_http_response*));
	*ptr = resp;
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, dlua_http_resp_gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");

	luaL_setfuncs(L, dovecot_http_response_methods, 0);
}

static void dlua_http_response_input_payload(struct dlua_http_response_payload_context *ctx)
{
	const unsigned char *data;
	size_t size;
	int ret;

	/* read payload */
	while ((ret=i_stream_read_more(ctx->payload_istream, &data, &size)) > 0) {
		str_append_data(ctx->payload_str, data, size);
		i_stream_skip(ctx->payload_istream, size);
	}

	if (ctx->payload_istream->stream_errno != 0) {
		ctx->error = p_strdup_printf(ctx->pool,
			"Response payload read error: %s",
			i_stream_get_error(ctx->payload_istream));
	}
	if (ret == 0) {
		e_debug(ctx->event, "DEBUG: REQUEST: NEED MORE DATA");
		/* we will be called again for this request */
	} else {
		if (ctx->payload_istream->stream_errno != 0) {
			e_error(ctx->event, "ERROR: REQUEST PAYLOAD READ ERROR: %s",
				i_stream_get_error(ctx->payload_istream));
		} else
			e_debug(ctx->event, "DEBUG: REQUEST: Finished");
		io_remove(&ctx->io);
		i_free(ctx);
	}
}

static void dlua_http_response_read_payload(const struct http_response *response,
					   struct dlua_http_response *dlua_resp)
{
	struct dlua_http_response_payload_context *ctx =
		i_new(struct dlua_http_response_payload_context ,1);
	ctx->payload_istream = response->payload;
	ctx->io = io_add_istream(response->payload,
			dlua_http_response_input_payload, ctx);
	ctx->payload_str = dlua_resp->payload;
	ctx->pool = dlua_resp->pool;
	ctx->event = dlua_resp->event;
	dlua_http_response_input_payload(ctx);
}

static void
dlua_http_request_callback(const struct http_response *response, lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);

	/* we need a keep a copy of http_response, otherwise the data will be
	 * lost when the object is freed. */
	pool_t pool = pool_alloconly_create("http_response", 1024);
	struct dlua_http_response *resp = p_new(pool, struct dlua_http_response, 1);
	resp->pool = pool;
	resp->date = response->date;
	resp->version_major = response->version_major;
	resp->version_minor = response->version_minor;
	resp->status = response->status;
	resp->reason = p_strdup(resp->pool, response->reason);
	resp->location = p_strdup(resp->pool, response->location);
	resp->date = response->date;
	resp->retry_after = response->retry_after;
	resp->payload = str_new(resp->pool, 528);
	resp->event = script->event;
	p_array_init(&resp->headers, resp->pool, 2);

	const ARRAY_TYPE(http_header_field) *hdrs;
	const struct http_header_field *hdr;
	struct http_header_field *hdr_cpy;

	hdrs = http_response_header_get_fields(response);
	if (hdrs != NULL) {
		array_foreach(hdrs, hdr) {
			hdr_cpy = array_append_space(&resp->headers);
			hdr_cpy->name = p_strdup(resp->pool, hdr->name);
			hdr_cpy->size = hdr->size;
			hdr_cpy->value = p_strdup(resp->pool, hdr->value);
		}
	}

	if (response->payload != NULL) {
		/* got payload */
		dlua_http_response_read_payload(response, resp);
	}

	dlua_push_http_response(L, resp);
}

static int dlua_http_request_new(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);

	const char *url, *method = "GET";
	struct http_client_request *http_req;
	struct http_url *http_url;
	const char *error;
	struct http_client *client = dlua_check_http_client(L, 1);

	luaL_checktype(L, 2, LUA_TTABLE);

	lua_getfield(L, -1, "url");
	if (lua_isnil(L, -1))
		return luaL_error(L, "cannot create request: url not specified");
	else
		url = luaL_checkstring(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, -1, "method");
	if (!lua_isnil(L, -1))
		method = luaL_checkstring(L, -1);
	lua_pop(L, 1);

	if (http_url_parse(url, NULL, HTTP_URL_ALLOW_USERINFO_PART, pool_datastack_create(),
			   &http_url, &error) < 0) {
		return luaL_error(L, "Failed to parse url %s: %s", url, error);
		return -1;
	}

	if (http_url->have_ssl && client->set.ssl == NULL) {
		return luaL_error(L, "TLS not enabled, cannot submit https request");
	}
	http_req = http_client_request_url(client, method, http_url,
					   dlua_http_request_callback, L);

	dlua_push_http_request(L, http_req);
	return 1;
}

static const luaL_Reg dovecot_http_client_methods[] = {
	{ "request", dlua_http_request_new },
	{ NULL, NULL }
};

static void dlua_push_http_client(lua_State *L, struct http_client *client)
{
	luaL_checkstack(L, 3, "out of memory");
	lua_createtable(L, 0, 1);
	luaL_setmetatable(L, DLUA_HTTP_CLIENT);

	/* we need to attach gc to userdata to support older lua*/
	struct http_client **ptr = lua_newuserdata(L, sizeof(struct http_client*));
	*ptr = client;
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, dlua_http_client_gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");

	luaL_setfuncs(L, dovecot_http_client_methods, 0);
}

#define CLIENT_SETTING_STR(field) \
	if (dlua_table_get_string_by_str(L, -1, #field, &(set->field)) < 0) { \
		*error_r = t_strdup_printf("%s: string expected", #field); return -1; }
#define CLIENT_SETTING_UINT(field) \
	if (dlua_table_get_uint_by_str(L, -1, #field, &(set->field)) < 0) { \
		*error_r = t_strdup_printf("%s: non-negative number expected", #field); return -1; }
#define CLIENT_SETTING_BOOL(field) \
	if (dlua_table_get_bool_by_str(L, -1, #field, &(set->field)) < 0) { \
		*error_r = t_strdup_printf("%s: boolean expected", #field); return -1; }

static int parse_client_settings(lua_State *L, struct http_client_settings *set,
				 const char **error_r)
{
	struct http_url *parsed_url;
	const char *proxy_url;
	const struct master_service_settings *master_set =
		master_service_settings_get(master_service);
	/* need to figure out socket dir */
	set->dns_client_socket_path = t_strconcat(master_set->base_dir, "/dns-client", NULL);
	CLIENT_SETTING_STR(user_agent);
	CLIENT_SETTING_STR(rawlog_dir);
	CLIENT_SETTING_UINT(max_idle_time_msecs);
/* FIXME: Enable when asynchronous calls are supported
*	CLIENT_SETTING_UINT(max_parallel_connections);
*	CLIENT_SETTING_UINT(max_pipelined_requests);
*/
	CLIENT_SETTING_BOOL(no_auto_redirect);
	CLIENT_SETTING_BOOL(no_auto_retry);
	CLIENT_SETTING_UINT(max_redirects);
	CLIENT_SETTING_UINT(max_attempts);
	CLIENT_SETTING_UINT(max_connect_attempts);
	CLIENT_SETTING_UINT(connect_backoff_time_msecs);
	CLIENT_SETTING_UINT(connect_backoff_max_time_msecs);
	CLIENT_SETTING_UINT(request_absolute_timeout_msecs);
	CLIENT_SETTING_UINT(request_timeout_msecs);
	CLIENT_SETTING_UINT(connect_timeout_msecs);
	CLIENT_SETTING_UINT(soft_connect_timeout_msecs);
	CLIENT_SETTING_UINT(max_auto_retry_delay_secs);
	CLIENT_SETTING_BOOL(debug);

	if (dlua_table_get_string_by_str(L, -1, "proxy_url", &proxy_url) > 0) {
		if (http_url_parse(proxy_url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
				   pool_datastack_create(), &parsed_url, error_r) < 0) {
			*error_r = t_strdup_printf("proxy_url is invalid: %s",
						   *error_r);
			return -1;
		}
		set->proxy_url = parsed_url;
		set->proxy_username = parsed_url->user;
		set->proxy_password = parsed_url->password;
	}

	lua_getfield(L, -1, "event_parent");
	if (!lua_isnil(L, -1))
		set->event_parent = dlua_check_event(L, -1);

	return 0;
}

static int dlua_http_client_new(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	luaL_checktype(L, 1, LUA_TTABLE);

	struct http_client *client;
	struct http_client_settings http_set;
	struct ssl_iostream_settings ssl_set;
	const char *error;

	i_zero(&http_set);

	if (parse_client_settings(L, &http_set, &error) < 0)
		luaL_error(L, "Invalid HTTP client setting: %s", error);

	const struct master_service_ssl_settings *master_ssl_set =
		master_service_settings_get_root_set(master_service,
			&master_service_ssl_setting_parser_info);
	master_service_ssl_client_settings_to_iostream_set(master_ssl_set,
		pool_datastack_create(), &ssl_set);
	http_set.ssl = &ssl_set;

	client = http_client_init(&http_set);
	dlua_push_http_client(L, client);
	return 1;
}

static const luaL_Reg dovecot_http_methods[] = {
	{ "client", dlua_http_client_new },
	{ NULL, NULL }
};

void dlua_dovecot_http_register(struct dlua_script *script)
{
	i_assert(script != NULL);

	lua_State *L = script->L;

	/* push dovecot table on the stack */
	dlua_get_dovecot(L);

	/* populate http methods in a table and add them as dovecot.http */
	lua_newtable(L);
	luaL_setfuncs(L, dovecot_http_methods, 0);
	lua_setfield(script->L, -2, DLUA_DOVECOT_HTTP);
	lua_pop(script->L, 1);
}
