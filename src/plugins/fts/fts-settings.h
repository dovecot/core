#ifndef FTS_SETTINGS_H
#define FTS_SETTINGS_H


/* <settings checks> */
#define FTS_FILTER		"fts"
#define FTS_FILTER_DECODER_TIKA	"fts_decoder_tika"

enum fts_enforced {
	FTS_ENFORCED_NO,
	FTS_ENFORCED_YES,
	FTS_ENFORCED_BODY,
};
enum fts_decoder {
	FTS_DECODER_NO,
	FTS_DECODER_TIKA,
	FTS_DECODER_SCRIPT,
};
/* </settings checks> */

struct fts_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) header_excludes;
	ARRAY_TYPE(const_string) header_includes;
	const char *decoder_driver;
	const char *decoder_script_socket_path;
	const char *decoder_tika_url;
	const char *driver;
	const char *enforced;
	unsigned int autoindex_max_recent_msgs;
	unsigned int index_timeout;
	uoff_t message_max_size;
	bool autoindex;

	enum fts_enforced parsed_enforced;
	enum fts_decoder parsed_decoder_driver;
};

extern const struct setting_parser_info fts_setting_parser_info;

#endif
