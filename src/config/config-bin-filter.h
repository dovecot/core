#ifndef CONFIG_BIN_FILTER_H
#define CONFIG_BIN_FILTER_H

struct config_filter_parser;

/* Write the settings filter records to the binary config (see
   lib-settings/settings-bin-filter.h). Returns the primary name for each
   filter, or NULL if the filter has no names. The primary name is the
   include group name for group filters, otherwise the innermost filter
   name. */
void config_bin_filters_write(struct ostream *output,
			      struct config_filter_parser *const *filters,
			      pool_t pool, const char ***primary_names_r);

/* Write the filter index for a settings block. filter_indexes[] contains the
   (global) filter index for each of the block's filters. */
void config_bin_filter_index_write(struct ostream *output,
				   const char *const *primary_names,
				   const uint32_t *filter_indexes,
				   uint32_t filter_count);

#endif
