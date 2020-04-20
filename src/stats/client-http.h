#ifndef CLIENT_HTTP_H
#define CLIENT_HTTP_H

struct master_service_connection;
struct http_server_request;

typedef void
(stats_http_resource_callback_t)(void *context,
				 struct http_server_request *req,
				 const char *sub_path);

void client_http_create(struct master_service_connection *conn);

void stats_http_resource_add(const char *path, const char *title,
			     stats_http_resource_callback_t *callback,
			     void *context);
#define stats_http_resource_add(path, title, callback, context) \
	stats_http_resource_add(path, title, \
		(stats_http_resource_callback_t *)callback, \
		(TRUE ? context : \
		 CALLBACK_TYPECHECK(callback, void (*)( \
			typeof(context), struct http_server_request *req, \
			const char *sub_path))))

void client_http_init(const struct stats_settings *set);
void client_http_deinit(void);

#endif
