/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-bin-filter.h"

static int
settings_bin_read_uint32(const unsigned char *data, size_t data_size,
			 size_t *offset, const char *name, uint32_t *num_r,
			 const char **error_r)
{
	if (data_size - *offset < sizeof(*num_r)) {
		*error_r = t_strdup_printf(
			"Area too small when reading uint of '%s' "
			"(offset=%zu, size=%zu)", name, *offset, data_size);
		return -1;
	}
	memcpy(num_r, data + *offset, sizeof(*num_r));
	*offset += sizeof(*num_r);
	return 0;
}

static inline const char *
settings_bin_filter_str(const struct settings_bin_filters *filters,
			uint32_t rel_offset)
{
	if (rel_offset == 0)
		return NULL;
	return (const char *)filters->base + rel_offset;
}

static inline const char *
settings_bin_filter_name(const struct settings_bin_filters *filters,
			 const struct settings_bin_filter *filter,
			 uint32_t idx)
{
	const uint32_t *name_offsets = (const void *)
		(filters->base + filter->filter_names_offset);
	i_assert(idx < filter->filter_names_count);
	return settings_bin_filter_str(filters, name_offsets[idx]);
}

/* Check that the string area begins after the records and is within the
   filters area. */
static bool
settings_bin_filter_offset_is_valid(const struct settings_bin_filters *filters,
				    uint32_t rel_offset)
{
	return rel_offset >= filters->records_size &&
		rel_offset < filters->size;
}

static int
settings_bin_filter_check_str(const struct settings_bin_filters *filters,
			      uint32_t filter_idx, const char *name,
			      uint32_t rel_offset, const char **error_r)
{
	if (rel_offset == 0)
		return 0;
	if (!settings_bin_filter_offset_is_valid(filters, rel_offset) ||
	    memchr(filters->base + rel_offset, '\0',
		   filters->size - rel_offset) == NULL) {
		*error_r = t_strdup_printf(
			"Filter %u %s offset %u points outside area (size=%zu)",
			filter_idx, name, rel_offset, filters->size);
		return -1;
	}
	return 0;
}

static int
settings_bin_filter_check_area(const struct settings_bin_filters *filters,
			       uint32_t filter_idx, const char *name,
			       uint32_t rel_offset, uint64_t size,
			       const char **error_r)
{
	if (rel_offset == 0)
		return 0;
	if (!settings_bin_filter_offset_is_valid(filters, rel_offset) ||
	    rel_offset % sizeof(uint32_t) != 0 ||
	    size > filters->size - rel_offset) {
		*error_r = t_strdup_printf(
			"Filter %u %s offset %u points outside area (size=%zu)",
			filter_idx, name, rel_offset, filters->size);
		return -1;
	}
	return 0;
}

static int
settings_bin_filter_check(const struct settings_bin_filters *filters,
			  uint32_t filter_idx,
			  const struct settings_bin_filter *filter,
			  const char **error_r)
{
	struct settings_bin_filter_net net;

	if (settings_bin_filter_check_str(filters, filter_idx, "protocol",
					  filter->protocol_offset,
					  error_r) < 0 ||
	    settings_bin_filter_check_str(filters, filter_idx, "local_name",
					  filter->local_name_offset,
					  error_r) < 0 ||
	    settings_bin_filter_check_area(filters, filter_idx, "local_net",
					   filter->local_net_offset,
					   sizeof(net), error_r) < 0 ||
	    settings_bin_filter_check_area(filters, filter_idx, "remote_net",
					   filter->remote_net_offset,
					   sizeof(net), error_r) < 0 ||
	    settings_bin_filter_check_area(filters, filter_idx, "filter names",
					   filter->filter_names_offset,
					   (uint64_t)filter->filter_names_count *
					   sizeof(uint32_t), error_r) < 0)
		return -1;
	if (filter->filter_names_count > 0 &&
	    filter->filter_names_offset == 0) {
		*error_r = t_strdup_printf(
			"Filter %u has %u names, but no names offset",
			filter_idx, filter->filter_names_count);
		return -1;
	}

	uint32_t offsets[2] = {
		filter->local_net_offset, filter->remote_net_offset
	};
	for (unsigned int i = 0; i < N_ELEMENTS(offsets); i++) {
		if (offsets[i] == 0)
			continue;
		memcpy(&net, filters->base + offsets[i], sizeof(net));
		if ((net.family != 4 || net.bits > 32) &&
		    (net.family != 6 || net.bits > 128)) {
			*error_r = t_strdup_printf(
				"Filter %u has invalid net (family=%u bits=%u)",
				filter_idx, net.family, net.bits);
			return -1;
		}
	}

	if ((filter->flags & ENUM_NEGATE(SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT |
					 SETTINGS_BIN_FILTER_FLAG_GROUP)) != 0) {
		*error_r = t_strdup_printf("Filter %u has unknown flags 0x%x",
					   filter_idx, filter->flags);
		return -1;
	}
	if ((filter->flags & SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT) != 0 &&
	    filter->protocol_offset == 0) {
		*error_r = t_strdup_printf(
			"Filter %u has negated protocol without protocol",
			filter_idx);
		return -1;
	}

	const uint32_t *name_offsets = (const void *)
		(filters->base + filter->filter_names_offset);
	bool have_group_name = FALSE;
	for (uint32_t i = 0; i < filter->filter_names_count; i++) {
		if (name_offsets[i] == 0) {
			*error_r = t_strdup_printf(
				"Filter %u name %u offset is 0", filter_idx, i);
			return -1;
		}
		if (settings_bin_filter_check_str(filters, filter_idx,
						  "filter name",
						  name_offsets[i],
						  error_r) < 0)
			return -1;
		if (settings_bin_filter_str(filters, name_offsets[i])[0] ==
		    SETTINGS_INCLUDE_GROUP_PREFIX)
			have_group_name = TRUE;
	}
	if (have_group_name !=
	    ((filter->flags & SETTINGS_BIN_FILTER_FLAG_GROUP) != 0)) {
		*error_r = t_strdup_printf(
			"Filter %u group flag doesn't match its names",
			filter_idx);
		return -1;
	}
	return 0;
}

static bool
settings_bin_filter_match_service(const struct settings_bin_filters *filters,
				  const struct settings_bin_filter *filter,
				  const char *service_name)
{
	const char *name, *filter_service;

	for (uint32_t i = 0; i < filter->filter_names_count; i++) {
		name = settings_bin_filter_name(filters, filter, i);
		if (str_begins(name, "service/", &filter_service) &&
		    strcmp(filter_service, service_name) != 0)
			return FALSE;
	}
	return TRUE;
}

static bool
settings_bin_filters_protocol_exists(const ARRAY_TYPE(const_string) *protocols,
				     const char *protocol, bool op_not)
{
	const char *value;

	array_foreach_elem(protocols, value) {
		bool value_not = value[0] == '!';
		if (value_not == op_not &&
		    strcmp(value_not ? value + 1 : value, protocol) == 0)
			return TRUE;
	}
	return FALSE;
}

int settings_bin_filters_read(struct settings_bin_filters *filters_r,
			      pool_t pool, const unsigned char *data,
			      size_t data_size, const char *protocol_name,
			      const char *service_name,
			      ARRAY_TYPE(const_string) *protocols,
			      size_t *size_r, const char **error_r)
{
	size_t offset = 0;
	uint32_t count, strings_size;

	i_zero(filters_r);
	if (settings_bin_read_uint32(data, data_size, &offset,
				     "filters count", &count, error_r) < 0)
		return -1;
	if (settings_bin_read_uint32(data, data_size, &offset,
				     "filters strings size", &strings_size,
				     error_r) < 0)
		return -1;
	/* The relative offsets are 32bit, so the whole area must fit into
	   32 bits. */
	uint64_t records_size =
		(uint64_t)count * sizeof(struct settings_bin_filter);
	uint64_t filters_size = records_size + strings_size;
	if (filters_size > UINT32_MAX ||
	    filters_size > data_size - offset) {
		*error_r = t_strdup_printf(
			"Filters area points outside file "
			"(count=%u, strings_size=%u, size=%zu)",
			count, strings_size, data_size - offset);
		return -1;
	}
	filters_r->count = count;
	filters_r->records_size = records_size;
	filters_r->size = filters_size;
	filters_r->base = data + offset;
	filters_r->records = (const void *)filters_r->base;
	filters_r->never = p_new(pool, uint64_t, count / 64 + 1);

	for (uint32_t i = 0; i < count; i++) {
		const struct settings_bin_filter *filter =
			&filters_r->records[i];
		if (settings_bin_filter_check(filters_r, i, filter,
					      error_r) < 0)
			return -1;

		bool never = FALSE;
		const char *protocol =
			settings_bin_filter_str(filters_r,
						filter->protocol_offset);
		if (protocol != NULL) {
			bool op_not = (filter->flags &
				SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT) != 0;
			if (!settings_bin_filters_protocol_exists(protocols,
								  protocol,
								  op_not)) {
				const char *value = !op_not ?
					t_strdup(protocol) :
					t_strconcat("!", protocol, NULL);
				array_push_back(protocols, &value);
			}

			if (protocol_name != NULL && !op_not &&
			    strcmp(protocol_name, protocol) != 0) {
				/* protocol doesn't match */
				never = TRUE;
			}
		}
		if (service_name != NULL &&
		    !settings_bin_filter_match_service(filters_r, filter,
						       service_name)) {
			/* service name doesn't match */
			never = TRUE;
		}
		if (never)
			bit64_set(filters_r->never, i);
	}
	*size_r = offset + filters_size;
	return 0;
}
