/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "primes.h"
#include "ostream.h"
#include "settings.h"
#include "settings-bin-filter.h"
#include "config-filter.h"
#include "config-parser.h"
#include "config-bin-filter.h"

struct config_bin_filters {
	/* Size of all the fixed size records. The strings area begins after
	   them. */
	uint32_t records_size;
	buffer_t *records;
	buffer_t *strings;
};

static uint32_t config_bin_filters_offset(struct config_bin_filters *bf)
{
	i_assert(bf->records_size + bf->strings->used <= UINT32_MAX);
	return bf->records_size + bf->strings->used;
}

static void config_bin_filters_align(struct config_bin_filters *bf)
{
	if (bf->strings->used % sizeof(uint32_t) != 0) {
		buffer_append_zero(bf->strings, sizeof(uint32_t) -
				   bf->strings->used % sizeof(uint32_t));
	}
}

static uint32_t
config_bin_filters_add_str(struct config_bin_filters *bf, const char *str)
{
	uint32_t offset = config_bin_filters_offset(bf);
	buffer_append(bf->strings, str, strlen(str) + 1);
	return offset;
}

static uint32_t
config_bin_filters_add_net(struct config_bin_filters *bf,
			   const struct ip_addr *ip, unsigned int bits)
{
	struct settings_bin_filter_net net;

	i_zero(&net);
	net.bits = bits;
	if (IPADDR_IS_V4(ip)) {
		net.family = 4;
		memcpy(net.addr, &ip->u.ip4, sizeof(ip->u.ip4));
	} else {
		i_assert(IPADDR_IS_V6(ip));
		net.family = 6;
		memcpy(net.addr, &ip->u.ip6, sizeof(ip->u.ip6));
		net.scope_id = ip->scope_id;
	}
	config_bin_filters_align(bf);
	uint32_t offset = config_bin_filters_offset(bf);
	buffer_append(bf->strings, &net, sizeof(net));
	return offset;
}

static void
config_bin_filter_fill(struct config_bin_filters *bf,
		       const struct config_filter *filter,
		       struct settings_bin_filter *rec_r,
		       const char **primary_name_r)
{
	ARRAY_TYPE(const_string) names;
	const char *name, *group_name = NULL;

	i_zero(rec_r);
	t_array_init(&names, 4);
	for (; filter != NULL; filter = filter->parent) {
		/* Only the innermost protocol / local_name / net is used.
		   The config parser doesn't allow nesting protocols, and it
		   requires the inner nets and local_names to be inside the
		   outer ones. */
		if (filter->protocol != NULL && rec_r->protocol_offset == 0) {
			const char *protocol = filter->protocol;
			if (protocol[0] == '!') {
				rec_r->flags |=
					SETTINGS_BIN_FILTER_FLAG_PROTOCOL_NOT;
				protocol++;
			}
			rec_r->protocol_offset =
				config_bin_filters_add_str(bf, protocol);
		}
		if (filter->local_name != NULL &&
		    rec_r->local_name_offset == 0) {
			rec_r->local_name_offset =
				config_bin_filters_add_str(bf,
							   filter->local_name);
		}
		if (filter->local_bits > 0 && rec_r->local_net_offset == 0) {
			rec_r->local_net_offset =
				config_bin_filters_add_net(bf,
					&filter->local_net, filter->local_bits);
		}
		if (filter->remote_bits > 0 && rec_r->remote_net_offset == 0) {
			rec_r->remote_net_offset =
				config_bin_filters_add_net(bf,
					&filter->remote_net, filter->remote_bits);
		}

		if (filter->filter_name_array) {
			const char *p = strchr(filter->filter_name, '/');
			i_assert(p != NULL);
			name = t_strdup_printf("%s/%s",
				t_strdup_until(filter->filter_name, p),
				settings_section_escape(p + 1));
			array_push_back(&names, &name);
			rec_r->named_list_filter_count++;
			if (filter->filter_name[0] ==
			    SETTINGS_INCLUDE_GROUP_PREFIX) {
				rec_r->flags |= SETTINGS_BIN_FILTER_FLAG_GROUP;
				group_name = name;
			}
		} else if (filter->filter_name != NULL) {
			array_push_back(&names, &filter->filter_name);
		}
	}

	/* The filter is indexed by its primary name: the include group name
	   for groups, otherwise the innermost filter name. */
	if (group_name != NULL)
		*primary_name_r = group_name;
	else if (array_count(&names) > 0)
		*primary_name_r = array_idx_elem(&names, 0);
	else
		*primary_name_r = NULL;

	if (array_count(&names) == 0)
		return;

	unsigned int i, names_count = array_count(&names);
	uint32_t *name_offsets = t_new(uint32_t, names_count);
	for (i = 0; i < names_count; i++) {
		name_offsets[i] = config_bin_filters_add_str(bf,
			array_idx_elem(&names, i));
	}
	config_bin_filters_align(bf);
	rec_r->filter_names_offset = config_bin_filters_offset(bf);
	rec_r->filter_names_count = names_count;
	buffer_append(bf->strings, name_offsets,
		      sizeof(*name_offsets) * names_count);
}

void config_bin_filters_write(struct ostream *output,
			      struct config_filter_parser *const *filters,
			      pool_t pool, const char ***primary_names_r)
{
	unsigned int i, filter_count = 0;

	while (filters[filter_count] != NULL) filter_count++;

	struct config_bin_filters bf = {
		.records_size = sizeof(struct settings_bin_filter) *
			filter_count,
		.records = buffer_create_dynamic(default_pool,
			sizeof(struct settings_bin_filter) * filter_count),
		.strings = buffer_create_dynamic(default_pool, 1024),
	};
	const char **primary_names = p_new(pool, const char *, filter_count);

	for (i = 0; i < filter_count; i++) T_BEGIN {
		struct settings_bin_filter rec;
		const char *primary_name;

		config_bin_filter_fill(&bf, &filters[i]->filter,
				       &rec, &primary_name);
		buffer_append(bf.records, &rec, sizeof(rec));
		primary_names[i] = p_strdup(pool, primary_name);
	} T_END;
	config_bin_filters_align(&bf);

	/* 32bit padding */
	if (output->offset % sizeof(uint32_t) != 0) {
		uint32_t align = 0;
		o_stream_nsend(output, &align, sizeof(uint32_t) -
			       output->offset % sizeof(uint32_t));
	}
	uint32_t num32 = filter_count;
	o_stream_nsend(output, &num32, sizeof(num32));
	i_assert(bf.strings->used <= UINT32_MAX);
	num32 = bf.strings->used;
	o_stream_nsend(output, &num32, sizeof(num32));
	o_stream_nsend(output, bf.records->data, bf.records->used);
	o_stream_nsend(output, bf.strings->data, bf.strings->used);
	buffer_free(&bf.records);
	buffer_free(&bf.strings);
	*primary_names_r = primary_names;
}

struct config_filter_index_entry {
	const char *name;
	uint32_t block_filter_idx;
};

static int
config_filter_index_entry_cmp(const struct config_filter_index_entry *e1,
			      const struct config_filter_index_entry *e2)
{
	int ret = strcmp(e1->name, e2->name);
	if (ret != 0)
		return ret;
	/* descending order */
	if (e1->block_filter_idx > e2->block_filter_idx)
		return -1;
	if (e1->block_filter_idx < e2->block_filter_idx)
		return 1;
	return 0;
}

static void
config_filter_index_append_list(buffer_t *buf,
				const struct config_filter_index_entry *entries,
				unsigned int count)
{
	uint32_t num32 = count;
	buffer_append(buf, &num32, sizeof(num32));
	for (unsigned int i = 0; i < count; i++) {
		num32 = entries[i].block_filter_idx;
		buffer_append(buf, &num32, sizeof(num32));
	}
}

void config_bin_filter_index_write(struct ostream *output,
				   const char *const *primary_names,
				   const uint32_t *filter_indexes,
				   uint32_t filter_count)
{
	ARRAY(struct config_filter_index_entry) entries, noname_entries;
	struct config_filter_index_entry *entry;
	const struct config_filter_index_entry *ent;
	unsigned int i, count, names_count = 0;
	uint32_t num32, hash_table_size = 0;

	t_array_init(&entries, filter_count);
	t_array_init(&noname_entries, 8);
	/* Go through the filters in reverse order, so the lists are in
	   descending order. */
	for (uint32_t idx = filter_count; idx > 0; ) {
		idx--;
		const char *name = primary_names[filter_indexes[idx]];
		if (name == NULL)
			entry = array_append_space(&noname_entries);
		else
			entry = array_append_space(&entries);
		entry->name = name;
		entry->block_filter_idx = idx;
	}
	array_sort(&entries, config_filter_index_entry_cmp);
	ent = array_get(&entries, &count);
	for (i = 0; i < count; i++) {
		if (i == 0 || strcmp(ent[i-1].name, ent[i].name) != 0)
			names_count++;
	}
	/* Use linear probing with at most 50% load */
	if (names_count > 0)
		hash_table_size = primes_closest(names_count * 2);
	i_assert(hash_table_size == 0 || hash_table_size > names_count);

	buffer_t *buf = t_buffer_create(256);
	/* hash table nodes count */
	buffer_append(buf, &hash_table_size, sizeof(hash_table_size));
	/* reserve space for the hash table */
	size_t hash_table_offset = buf->used;
	buffer_append_zero(buf, sizeof(uint32_t) * 2 * hash_table_size);
	/* reserve space for the no-name filter list offset */
	size_t noname_offset = buf->used;
	buffer_append_zero(buf, sizeof(uint32_t));

	num32 = buf->used;
	buffer_write(buf, noname_offset, &num32, sizeof(num32));
	config_filter_index_append_list(buf, array_front(&noname_entries),
					array_count(&noname_entries));

	for (i = 0; i < count; ) {
		const char *name = ent[i].name;
		unsigned int start = i;
		for (i++; i < count && strcmp(ent[i].name, name) == 0; i++) ;

		uint32_t key_hash = str_stable_hash(name) % hash_table_size;
		size_t node_offset;
		uint32_t node[2];
		for (;;) {
			node_offset = hash_table_offset +
				key_hash * sizeof(uint32_t) * 2;
			memcpy(node, CONST_PTR_OFFSET(buf->data, node_offset),
			       sizeof(node));
			if (node[0] == 0)
				break;
			key_hash = (key_hash + 1) % hash_table_size;
		}

		node[0] = buf->used;
		buffer_append(buf, name, strlen(name) + 1);
		if (buf->used % sizeof(uint32_t) != 0) {
			buffer_append_zero(buf, sizeof(uint32_t) -
					   buf->used % sizeof(uint32_t));
		}
		node[1] = buf->used;
		config_filter_index_append_list(buf, &ent[start], i - start);
		buffer_write(buf, node_offset, node, sizeof(node));
	}

	/* 32bit padding */
	if (output->offset % sizeof(uint32_t) != 0) {
		uint32_t align = 0;
		o_stream_nsend(output, &align, sizeof(uint32_t) -
			       output->offset % sizeof(uint32_t));
	}
	o_stream_nsend(output, buf->data, buf->used);
}
