#ifndef FTS_SETTINGS_H
#define FTS_SETTINGS_H


/* <settings checks> */
#define FTS_FILTER		"fts"
#define FTS_FILTER_DECODER_TIKA	"fts_decoder_tika"

enum fts_decoder {
	FTS_DECODER_NO,
	FTS_DECODER_TIKA,
	FTS_DECODER_SCRIPT,
};
/* </settings checks> */

struct fts_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fts;
	ARRAY_TYPE(const_string) header_excludes;
	ARRAY_TYPE(const_string) header_includes;
	const char *decoder_driver;
	const char *decoder_script_socket_path;
	const char *decoder_tika_url;
	const char *driver;
	bool search;
	const char *search_add_missing;
	bool search_read_fallback;
	unsigned int autoindex_max_recent_msgs;
	unsigned int search_timeout;
	uoff_t message_max_size;
	bool autoindex;

	enum fts_decoder parsed_decoder_driver;
	bool parsed_search_add_missing_body_only;
};

extern const struct setting_parser_info fts_setting_parser_info;

#endif
