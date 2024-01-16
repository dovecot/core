#ifndef FTS_SOLR_SETTINGS_H
#define FTS_SOLR_SETTINGS_H

/* <settings checks> */
#define FTS_SOLR_FILTER "fts_solr"
/* </settings checks> */

struct fts_solr_settings {
	pool_t pool;
	const char *url;
	unsigned int batch_size;
	bool soft_commit;
};

extern const struct setting_parser_info fts_solr_setting_parser_info;
int fts_solr_settings_get(struct event *event,
			  const struct setting_parser_info *info,
			  const struct fts_solr_settings **set,
			  const char **error_r);

#endif
