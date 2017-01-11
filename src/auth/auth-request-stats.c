/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "buffer.h"
#include "base64.h"
#include "stats.h"
#include "stats-connection.h"
#include "auth-stats.h"
#include "auth-request.h"
#include "auth-request-stats.h"

#define USER_STATS_SOCKET_NAME "stats-user"

static struct stats_connection *auth_stats_conn = NULL;
static struct stats_item *auth_stats_item;

struct auth_stats *auth_request_stats_get(struct auth_request *request)
{
	if (request->stats == NULL)
		request->stats = stats_alloc(request->pool);
	return stats_fill_ptr(request->stats, auth_stats_item);
}

void auth_request_stats_add_tempfail(struct auth_request *request)
{
	struct auth_stats *stats = auth_request_stats_get(request);

	stats->auth_db_tempfail_count++;
}

void auth_request_stats_send(struct auth_request *request)
{
	string_t *str;
	buffer_t *buf;

	/* we'll send stats only when the request is finished. this reduces
	   memory usage and is a bit simpler. auth requests are typically
	   pretty short lived anyway. */
	i_assert(!request->stats_sent);
	request->stats_sent = TRUE;

	if (request->stats == NULL) {
		/* nothing happened in this request - don't send it */
		return;
	}
	if (!request->set->stats)
		return;

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	stats_export(buf, request->stats);

	str = t_str_new(256);
	str_append(str, "ADD-USER\t");
	if (request->user != NULL)
		str_append_tabescaped(str, request->user);
	str_append_c(str, '\t');
	str_append_tabescaped(str, request->service);
	str_append_c(str, '\t');
	base64_encode(buf->data, buf->used, str);

	str_append_c(str, '\n');
	stats_connection_send(auth_stats_conn, str);
}

void auth_request_stats_init(void)
{
	auth_stats_conn = stats_connection_create(USER_STATS_SOCKET_NAME);
	auth_stats_item = stats_register(&auth_stats_vfuncs);
}

void auth_request_stats_deinit(void)
{
	stats_connection_unref(&auth_stats_conn);
	stats_unregister(&auth_stats_item);
}
