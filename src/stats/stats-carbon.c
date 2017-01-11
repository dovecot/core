/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "str.h"
#include "write-full.h"
#include "stats-carbon.h"

#define CARBON_SERVER_DEFAULT_PORT 2003

struct stats_send_ctx {
	pool_t pool;
	int fd;
	unsigned long to_msecs;
	const char *endpoint;
	const char *str;
	struct io *io;
	struct timeout *to;

	void (*callback)(void *);
	void *ctx;
};

void
stats_carbon_destroy(struct stats_send_ctx **_ctx)
{
	struct stats_send_ctx *ctx = *_ctx;
	*_ctx = NULL;

	if (ctx->io != NULL)
		io_remove(&ctx->io);
	if (ctx->to != NULL)
		timeout_remove(&ctx->to);
	if (ctx->fd != -1)
		i_close_fd(&ctx->fd);
	pool_unref(&ctx->pool);
}

static void
stats_carbon_callback(struct stats_send_ctx *ctx)
{
	i_assert(ctx->callback != NULL);
	void (*callback)(void *) = ctx->callback;
	ctx->callback = NULL;
	callback(ctx->ctx);
}

static void
stats_carbon_timeout(struct stats_send_ctx *ctx)
{
	i_error("Stats submit(%s) failed: endpoint timeout after %lu msecs",
		ctx->endpoint, ctx->to_msecs);
	stats_carbon_callback(ctx);
}

static void
stats_carbon_connected(struct stats_send_ctx *ctx)
{
	io_remove(&ctx->io);
	if ((errno = net_geterror(ctx->fd)) != 0) {
		i_error("connect(%s) failed: %m",
			ctx->endpoint);
		stats_carbon_callback(ctx);
		return;
	}
	if (write_full(ctx->fd, ctx->str, strlen(ctx->str)) < 0)
		i_error("write(%s) failed: %m",
			ctx->endpoint);
	stats_carbon_callback(ctx);
}

int
stats_carbon_send(const char *endpoint, const char *data,
		  void (*callback)(void *), void *cb_ctx,
		  struct stats_send_ctx **ctx_r)
{
	const char *host;
	in_port_t port;
	struct ip_addr ip;

	if (net_str2hostport(endpoint, CARBON_SERVER_DEFAULT_PORT,
			     &host, &port) < 0 ||
	    net_addr2ip(host, &ip) < 0) {
		i_error("stats_submit: Cannot parse endpoint '%s'",
			endpoint);
		return -1;
	}

	pool_t pool = pool_alloconly_create("stats carbon send", 1024);
	struct stats_send_ctx *ctx = p_new(pool,
					   struct stats_send_ctx, 1);
	ctx->pool = pool;
	ctx->str = p_strdup(ctx->pool, data);

	ctx->fd = net_connect_ip(&ip, port, NULL);
	if (ctx->fd < 0) {
		i_error("connect(%s) failed: %m", endpoint);
		stats_carbon_callback(ctx);
		return -1;
	}
	ctx->io = io_add(ctx->fd, IO_WRITE,
			 stats_carbon_connected,
			 ctx);

	/* give time for almost until next update
	   this is to ensure we leave a little pause between
           attempts. Multiplier 800 gives us 20% window, and
           ensures the number stays positive. */
	ctx->to_msecs = stats_settings->carbon_interval*800;
	ctx->to = timeout_add(ctx->to_msecs,
			      stats_carbon_timeout,
			      ctx);
	if (net_ipport2str(&ip, port, &host) < 0)
		i_unreached();
	ctx->endpoint = p_strdup(ctx->pool, host);
	ctx->callback = callback;
	ctx->ctx = cb_ctx;

	*ctx_r = ctx;

	return 0;
}
