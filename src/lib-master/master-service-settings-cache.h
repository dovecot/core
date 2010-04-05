#ifndef MASTER_SERVICE_SETTINGS_CACHE_H
#define MASTER_SERVICE_SETTINGS_CACHE_H

struct master_service_settings_cache *
master_service_settings_cache_init(struct master_service *service,
				   const char *module,
				   const char *service_name);
void master_service_settings_cache_deinit(struct master_service_settings_cache **cache);

int master_service_settings_cache_read(struct master_service_settings_cache *cache,
				       const struct master_service_settings_input *input,
				       const struct dynamic_settings_parser *dyn_parsers,
				       const struct setting_parser_context **parser_r,
				       const char **error_r);

#endif
