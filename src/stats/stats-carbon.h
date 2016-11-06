#ifndef STATS_CARBON
#define STATS_CARBON 1

struct stats_send_ctx;

int
stats_carbon_send(const char *endpoint, const char *data,
		  void (*callback)(void *), void *cb_ctx,
		  struct stats_send_ctx **ctx_r);
void
stats_carbon_destroy(struct stats_send_ctx **ctx);

#endif
