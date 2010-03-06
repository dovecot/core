#ifndef ZLIB_PLUGIN_H
#define ZLIB_PLUGIN_H

struct zlib_handler {
	const char *name;
	const char *ext;
	bool (*is_compressed)(struct istream *input);
	struct istream *(*create_istream)(struct istream *input,
					  bool log_errors);
	struct ostream *(*create_ostream)(struct ostream *output, int level);
};

extern const struct zlib_handler zlib_handlers[];

const struct zlib_handler *zlib_find_zlib_handler(const char *name);

void zlib_plugin_init(struct module *module);
void zlib_plugin_deinit(void);

#endif
