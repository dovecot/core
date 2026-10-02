#ifndef SETTINGS_BIN_FILTER_H
#define SETTINGS_BIN_FILTER_H

/* Settings filter records written to the binary config by the config process
   and read by lib-settings. See ../config/config-dump-full.c for the format
   description. Both sides are always the same build, so these structs are
   written as-is in native endianness. */

enum settings_bin_filter_flags {
	/* protocol_offset is negated: the filter matches only when the
	   protocol is different. */
	SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT	= 0x01,
	/* The filter is (inside) an include group definition. */
	SETTINGS_BIN_FILTER_FLAG_GROUP		= 0x02,
};

struct settings_bin_filter {
	/* enum settings_bin_filter_flags */
	uint32_t flags;
	/* Relative offsets from the beginning of the filter records. 0 means
	   the condition doesn't exist. */
	uint32_t protocol_offset;
	uint32_t local_name_offset;
	uint32_t local_net_offset;
	uint32_t remote_net_offset;
	/* Points to filter_names_count number of uint32_t relative offsets,
	   which point to NUL-terminated filter name strings. */
	uint32_t filter_names_offset;
	uint32_t filter_names_count;
	/* Number of named list filter elements in the filter */
	uint32_t named_list_filter_count;
};

struct settings_bin_filter_net {
	/* 4 = IPv4, 6 = IPv6 */
	uint8_t family;
	uint8_t bits;
	uint8_t unused[2];
	uint32_t scope_id;
	/* IPv4 address uses only the first 4 bytes */
	uint8_t addr[16];
};

/* Filter records read from the binary config. */
struct settings_bin_filters {
	const struct settings_bin_filter *records;
	/* Base for the records' relative offsets */
	const unsigned char *base;
	/* Size of the records */
	size_t records_size;
	/* Size of the records and the strings area */
	size_t size;
	uint32_t count;
	/* Bitmap of filters that can never match in this process (protocol or
	   service mismatch). */
	uint64_t *never;
};

/* Read and validate the filter records from the beginning of data. The data
   must be 32bit aligned. If protocol_name or service_name is non-NULL, the
   filters for other protocols/services are marked as never matching. The
   protocols used by the filters are added to protocols (prefixed with "!"
   if negated). Returns the number of bytes used from data, or -1 on error. */
int settings_bin_filters_read(struct settings_bin_filters *filters_r,
			      pool_t pool, const unsigned char *data,
			      size_t data_size, const char *protocol_name,
			      const char *service_name,
			      ARRAY_TYPE(const_string) *protocols,
			      size_t *size_r, const char **error_r);

static inline const struct settings_bin_filter *
settings_bin_filters_get(const struct settings_bin_filters *filters,
			 uint32_t idx)
{
	i_assert(idx < filters->count);
	return &filters->records[idx];
}

/* Returns TRUE if the filter can never match in this process. */
static inline bool
settings_bin_filters_never(const struct settings_bin_filters *filters,
			   uint32_t idx)
{
	i_assert(idx < filters->count);
	return bit64_get(filters->never, idx);
}

#endif
