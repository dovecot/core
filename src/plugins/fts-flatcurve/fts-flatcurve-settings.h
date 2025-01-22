#ifndef FTS_FLATCURVE_SETTINGS_H
#define FTS_FLATCURVE_SETTINGS_H

/* <settings checks> */
#define FTS_FLATCURVE_FILTER "fts_flatcurve"
/* </settings checks> */

struct fts_flatcurve_settings {
	pool_t pool;
	unsigned int commit_limit;
	unsigned int min_term_size;
	unsigned int optimize_limit;
	unsigned int rotate_count;
	unsigned int rotate_time;
	bool substring_search;
};

extern const struct setting_parser_info fts_flatcurve_setting_parser_info;

#endif
