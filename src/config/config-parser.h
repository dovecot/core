#ifndef __CONFIG_PARSER_H
#define __CONFIG_PARSER_H

void config_parsers_fix_parents(pool_t pool);

void config_parse_file(string_t *dest, const char *path, const char *service);

#endif
