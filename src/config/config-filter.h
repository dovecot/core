#ifndef CONFIG_FILTER_H
#define CONFIG_FILTER_H

#include "network.h"

struct master_service_settings_output;

struct config_filter {
	const char *service;
	/* local_name is for TLS SNI requests.
	   both local_name and local_bits can't be set at the same time. */
	const char *local_name;
	/* the hosts are used only in doveconf output */
	const char *local_host, *remote_host;
	struct ip_addr local_net, remote_net;
	unsigned int local_bits, remote_bits;
};

struct config_filter_parser {
	struct config_filter filter;
	const char *file_and_line;
	/* NULL-terminated array of parsers */
	struct config_module_parser *parsers;
};
ARRAY_DEFINE_TYPE(config_filter_parsers, struct config_filter_parser *);

struct config_filter_context *config_filter_init(pool_t pool);
void config_filter_deinit(struct config_filter_context **ctx);

/* Replace filter's parsers with given parser list. */
void config_filter_add_all(struct config_filter_context *ctx,
			   struct config_filter_parser *const *parsers);

/* Build new parsers from all existing ones matching the given filter. */
int config_filter_parsers_get(struct config_filter_context *ctx, pool_t pool,
			      const char *module,
			      const struct config_filter *filter,
			      struct config_module_parser **parsers_r,
			      struct master_service_settings_output *output_r,
			      const char **error_r);
void config_filter_parsers_free(struct config_module_parser *parsers);

/* Return a list of filters that are a subset of the given filter. */
struct config_filter_parser *const *
config_filter_find_subset(struct config_filter_context *ctx,
			  const struct config_filter *filter);

/* Returns TRUE if filter matches mask. */
bool config_filter_match(const struct config_filter *mask,
			 const struct config_filter *filter);
/* Returns TRUE if two filters are fully equal. */
bool config_filters_equal(const struct config_filter *f1,
			  const struct config_filter *f2);

#endif
