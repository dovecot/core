/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "dns-util.h"
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

static void
settings_bin_filter_net(const struct settings_bin_filters *filters,
			uint32_t rel_offset, struct ip_addr *ip_r,
			unsigned int *bits_r)
{
	struct settings_bin_filter_net net;

	memcpy(&net, filters->base + rel_offset, sizeof(net));
	i_zero(ip_r);
	if (net.family == 4) {
		ip_r->family = AF_INET;
		memcpy(&ip_r->u.ip4, net.addr, sizeof(ip_r->u.ip4));
	} else {
		ip_r->family = AF_INET6;
		memcpy(&ip_r->u.ip6, net.addr, sizeof(ip_r->u.ip6));
		ip_r->scope_id = net.scope_id;
	}
	*bits_r = net.bits;
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

bool settings_bin_filter_has_name(const struct settings_bin_filters *filters,
				  const struct settings_bin_filter *filter,
				  const char *name)
{
	for (uint32_t i = 0; i < filter->filter_names_count; i++) {
		if (strcmp(settings_bin_filter_name(filters, filter, i),
			   name) == 0)
			return TRUE;
	}
	return FALSE;
}

static const char *
settings_bin_filter_lookup_get_str(struct event *event, const char *key)
{
	const struct event_field *field =
		event_find_field_recursive(event, key);

	if (field == NULL || field->value_type != EVENT_FIELD_VALUE_TYPE_STR ||
	    field->value.str[0] == '\0')
		return NULL;
	return field->value.str;
}

static bool
settings_bin_filter_lookup_get_ip(struct event *event, const char *key,
				  struct ip_addr *ip_r)
{
	const struct event_field *field =
		event_find_field_recursive(event, key);

	if (field == NULL || field->value_type != EVENT_FIELD_VALUE_TYPE_IP)
		return FALSE;
	*ip_r = field->value.ip;
	return TRUE;
}

static void
settings_bin_filter_lookup_add_strlist_names(
	struct settings_bin_filter_lookup *lookup, struct event *event)
{
	const struct event_field *field;
	const char *name;

	for (; event != NULL; event = event_get_parent(event)) {
		field = event_find_field_nonrecursive(event,
				SETTINGS_EVENT_FILTER_NAME);
		if (field == NULL ||
		    field->value_type != EVENT_FIELD_VALUE_TYPE_STRLIST)
			continue;
		array_foreach_elem(&field->value.strlist, name)
			array_push_back(&lookup->filter_names, &name);
	}
}

void
settings_bin_filter_lookup_init(struct settings_bin_filter_lookup *lookup_r,
				struct event *event)
{
	/* This mirrors how event filters would match the event: the fields
	   are looked up recursively and the filter names are merged from the
	   event hierarchy and the global event. */
	i_zero(lookup_r);
	t_array_init(&lookup_r->filter_names, 8);
	lookup_r->protocol =
		settings_bin_filter_lookup_get_str(event, "protocol");
	lookup_r->local_name =
		settings_bin_filter_lookup_get_str(event, "local_name");
	lookup_r->have_local_ip =
		settings_bin_filter_lookup_get_ip(event, "local_ip",
						  &lookup_r->local_ip);
	lookup_r->have_remote_ip =
		settings_bin_filter_lookup_get_ip(event, "remote_ip",
						  &lookup_r->remote_ip);
	/* settings_get() already copied all the filter names in the event
	   hierarchy to the lookup event, but check the parents (and the
	   global event) as well in case they have strlists. */
	settings_bin_filter_lookup_add_strlist_names(lookup_r, event);
	settings_bin_filter_lookup_add_strlist_names(lookup_r,
						     event_get_global());
}

static bool settings_local_name_cmp(const char *value, const char *wanted_value)
{
	return dns_match_wildcard(value, wanted_value) == 0;
}

bool settings_bin_filter_match(const struct settings_bin_filters *filters,
			       const struct settings_bin_filter *filter,
			       const struct settings_bin_filter_lookup *lookup)
{
	const char *str;
	struct ip_addr net;
	unsigned int bits;

	if (filter->protocol_offset != 0) {
		str = settings_bin_filter_str(filters, filter->protocol_offset);
		bool match = lookup->protocol != NULL &&
			strcmp(str, lookup->protocol) == 0;
		bool op_not = (filter->flags &
			       SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT) != 0;
		if (match == op_not)
			return FALSE;
	}
	if (filter->local_name_offset != 0) {
		str = settings_bin_filter_str(filters,
					      filter->local_name_offset);
		if (lookup->local_name == NULL ||
		    !settings_local_name_cmp(lookup->local_name, str))
			return FALSE;
	}
	if (filter->local_net_offset != 0) {
		settings_bin_filter_net(filters, filter->local_net_offset,
					&net, &bits);
		if (!lookup->have_local_ip ||
		    !net_is_in_network(&lookup->local_ip, &net, bits))
			return FALSE;
	}
	if (filter->remote_net_offset != 0) {
		settings_bin_filter_net(filters, filter->remote_net_offset,
					&net, &bits);
		if (!lookup->have_remote_ip ||
		    !net_is_in_network(&lookup->remote_ip, &net, bits))
			return FALSE;
	}
	for (uint32_t i = 0; i < filter->filter_names_count; i++) {
		str = settings_bin_filter_name(filters, filter, i);
		if (array_lsearch(&lookup->filter_names, &str,
				  i_strcmp_p) == NULL)
			return FALSE;
	}
	return TRUE;
}
