#ifndef CONFIG_BIN_FILTER_H
#define CONFIG_BIN_FILTER_H

struct config_filter_parser;

/* Write the settings filter records to the binary config (see
   lib-settings/settings-bin-filter.h). */
void config_bin_filters_write(struct ostream *output,
			      struct config_filter_parser *const *filters);

#endif
