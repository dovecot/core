#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

void config_parse_file(pool_t dest_pool, ARRAY_TYPE(const_string) *dest,
		       const char *path, const char *service);

#endif
