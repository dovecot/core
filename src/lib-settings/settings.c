/* Copyright (c) 2005-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "event-filter.h"
#include "var-expand.h"
#include "wildcard-match.h"
#include "mmap-util.h"
#include "settings-parser.h"
#include "settings.h"

struct settings_override {
	int type;
	bool append;
	const char *key, *value;

	struct event_filter *filter;
	const char *last_filter_key, *last_filter_value;
};
ARRAY_DEFINE_TYPE(settings_override, struct settings_override);

struct settings_mmap_filter {
	struct event_filter *filter;
	bool empty_filter;

	const char *error; /* if non-NULL, accessing the block must fail */
	size_t start_offset, end_offset;
};

struct settings_mmap_block {
	const char *name;

	const char *error; /* if non-NULL, accessing the block must fail */
	size_t base_start_offset, base_end_offset;
	ARRAY(struct settings_mmap_filter) filters;
};

struct settings_mmap {
	int refcount;
	struct settings_root *root;

	void *mmap_base;
	size_t mmap_size;

	HASH_TABLE(const char *, struct settings_mmap_block *) blocks;
};

struct settings_root {
	pool_t pool;
	const char *protocol_name;
	struct settings_mmap *mmap;
	ARRAY_TYPE(settings_override) overrides;

	struct settings_mmap_pool *settings_pools;
};

struct settings_instance {
	pool_t pool;
	struct settings_mmap *mmap;
	ARRAY_TYPE(settings_override) overrides;
};

static const char *settings_override_type_names[] = {
	"userdb", "-o parameter", "hardcoded"
};
static_assert_array_size(settings_override_type_names,
			 SETTINGS_OVERRIDE_TYPE_COUNT);

static void
filter_string_parse_protocol(const char *filter_string,
			     ARRAY_TYPE(const_string) *protocols)
{
	const char *p = strstr(filter_string, "protocol=\"");
	if (p == NULL)
		return;
	const char *p2 = strchr(p + 10, '"');
	if (p2 == NULL)
		return;

	char *add_protocol = NULL;
	T_BEGIN {
		const char *protocol = t_strdup_until(p + 10, p2);
		if (p - filter_string > 4 && strcmp(p - 4, "NOT ") == 0)
			protocol = t_strconcat("!", protocol, NULL);
		if (array_lsearch(protocols, &protocol, i_strcmp_p) == NULL)
			add_protocol = i_strdup(protocol);
	} T_END;
	if (add_protocol != NULL) {
		const char *protocol = t_strdup(add_protocol);
		array_push_back(protocols, &protocol);
		i_free(add_protocol);
	}
}

static int
settings_block_read_size(struct settings_mmap *mmap,
			 size_t *offset, size_t end_offset,
			 const char *name, uint64_t *size_r,
			 const char **error_r)
{
	if (*offset + sizeof(*size_r) > end_offset) {
		*error_r = t_strdup_printf(
			"Area too small when reading size of '%s' "
			"(offset=%zu, end_offset=%zu, file_size=%zu)", name,
			*offset, end_offset, mmap->mmap_size);
		return -1;
	}
	*size_r = be64_to_cpu_unaligned(CONST_PTR_OFFSET(mmap->mmap_base, *offset));
	if (*size_r > end_offset - *offset - sizeof(*size_r)) {
		*error_r = t_strdup_printf(
			"'%s' points outside area "
			"(offset=%zu, size=%"PRIu64", end_offset=%zu, file_size=%zu)",
			name, *offset, *size_r, end_offset,
			mmap->mmap_size);
		return -1;
	}
	*offset += sizeof(*size_r);
	return 0;
}

static int
settings_block_read_str(struct settings_mmap *mmap,
			uoff_t *offset, uoff_t end_offset, const char *name,
			const char **str_r, const char **error_r)
{
	*str_r = (const char *)mmap->mmap_base + *offset;
	*offset += strlen(*str_r) + 1;
	if (*offset > end_offset) {
		*error_r = t_strdup_printf("'%s' points outside area "
			"(offset=%zu, end_offset=%zu, file_size=%zu)",
			name, *offset, end_offset, mmap->mmap_size);
		return -1;
	}
	return 0;
}

static int
settings_block_read(struct settings_mmap *mmap, uoff_t *_offset,
		    ARRAY_TYPE(const_string) *protocols, const char **error_r)
{
	uoff_t offset = *_offset;
	size_t block_size_offset = offset;
	const char *error;

	/* <block size> */
	uint64_t block_size;
	if (settings_block_read_size(mmap, &offset, mmap->mmap_size,
				     "block size", &block_size, error_r) < 0)
		return -1;
	size_t block_end_offset = offset + block_size;

	/* Verify that block ends with NUL. This way we can safely use strlen()
	   later on and we know it won't read past the mmaped memory area and
	   cause a crash. The NUL is either from the last settings value or
	   from the last error string. */
	if (((const char *)mmap->mmap_base)[block_end_offset-1] != '\0') {
		*error_r = t_strdup_printf(
			"Settings block doesn't end with NUL at offset %zu",
			block_end_offset-1);
		return -1;
	}

	/* <block name> */
	const char *block_name;
	if (settings_block_read_str(mmap, &offset, block_end_offset,
				    "block name", &block_name, error_r) < 0)
		return -1;

	struct settings_mmap_block *block =
		hash_table_lookup(mmap->blocks, block_name);
	if (block != NULL) {
		*error_r = t_strdup_printf(
			"Duplicate block name '%s' (offset=%zu)",
			block_name, block_size_offset);
		return -1;
	}
	block = i_new(struct settings_mmap_block, 1);
	block->name = block_name;
	hash_table_insert(mmap->blocks, block->name, block);

	/* <base settings size> */
	uint64_t base_settings_size;
	if (settings_block_read_size(mmap, &offset, block_end_offset,
				     "base settings size", &base_settings_size,
				     error_r) < 0)
		return -1;
	block->base_end_offset = offset + base_settings_size;

	/* <base settings error string> */
	if (settings_block_read_str(mmap, &offset,
				    block->base_end_offset,
				    "base settings error", &error,
				    error_r) < 0)
		return -1;
	if (error[0] != '\0')
		block->error = error;
	block->base_start_offset = offset;

	/* skip over the key-value pairs */
	offset = block->base_end_offset;

	/* filters */
	while (offset < block_end_offset) {
		/* <filter settings size> */
		uint64_t filter_settings_size;
		if (settings_block_read_size(mmap, &offset,
				block_end_offset, "filter settings size",
				&filter_settings_size, error_r) < 0)
			return -1;
		uint64_t filter_end_offset = offset + filter_settings_size;

		/* <filter string> */
		const char *filter_string;
		if (settings_block_read_str(mmap, &offset,
					    filter_end_offset, "filter string",
					    &filter_string, error_r) < 0)
			return -1;

		/* <filter settings error string> */
		const char *filter_error;
		if (settings_block_read_str(mmap, &offset,
					    filter_end_offset,
					    "filter settings error",
					    &filter_error, error_r) < 0)
			return -1;

		if (!array_is_created(&block->filters))
			i_array_init(&block->filters, 4);

		struct settings_mmap_filter *config_filter =
			array_append_space(&block->filters);
		config_filter->filter = event_filter_create();
		config_filter->empty_filter = filter_string[0] == '\0';
		config_filter->error = filter_error[0] == '\0' ?
			NULL : filter_error;
		config_filter->start_offset = offset;
		config_filter->end_offset = filter_end_offset;

		if (event_filter_parse_case_sensitive(filter_string,
				config_filter->filter, &error) < 0) {
			*error_r = t_strdup_printf(
				"Received invalid filter '%s': %s (offset=%zu)",
				filter_string, error, offset);
			return -1;
		}
		filter_string_parse_protocol(filter_string, protocols);

		/* skip over the key-value pairs */
		offset = filter_end_offset;
	}
	i_assert(offset == block_end_offset);
	*_offset = offset;
	return 0;
}

static void settings_mmap_free_blocks(struct settings_mmap *mmap)
{
	struct hash_iterate_context *iter =
		hash_table_iterate_init(mmap->blocks);
	const char *name;
	struct settings_mmap_block *block;

	while (hash_table_iterate(iter, mmap->blocks, &name, &block)) {
		if (array_is_created(&block->filters)) {
			struct settings_mmap_filter *config_filter;
			array_foreach_modifiable(&block->filters, config_filter)
				event_filter_unref(&config_filter->filter);
			array_free(&block->filters);
		}
		i_free(block);
	}
	hash_table_iterate_deinit(&iter);
}

static int
settings_mmap_parse(struct settings_mmap *mmap,
		    const char *const **specific_services_r,
		    const char **error_r)
{
	/*
	   See ../config/config-dump-full.c for the binary config file format
	   description.

	   Settings are read until the blob size is reached. There is no
	   padding/alignment. */
	const unsigned char *mmap_base = mmap->mmap_base;
	size_t mmap_size = mmap->mmap_size;
	ARRAY_TYPE(const_string) protocols;

	t_array_init(&protocols, 8);

	const char *magic_prefix = "DOVECOT-CONFIG\t";
	const unsigned int magic_prefix_len = strlen(magic_prefix);
	const unsigned char *eol = memchr(mmap_base, '\n', mmap_size);
	if (mmap_size < magic_prefix_len ||
	    memcmp(magic_prefix, mmap_base, magic_prefix_len) != 0 ||
	    eol == NULL) {
		*error_r = "File header doesn't begin with DOVECOT-CONFIG line";
		return -1;
	}
	if (mmap_base[magic_prefix_len] != '1' ||
	    mmap_base[magic_prefix_len+1] != '.') {
		*error_r = t_strdup_printf(
			"Unsupported config file version '%s'",
			t_strdup_until(mmap_base + magic_prefix_len, eol));
		return -1;
	}

	/* <settings full size> */
	size_t full_size_offset = eol - mmap_base + 1;
	uint64_t settings_full_size =
		be64_to_cpu_unaligned(mmap_base + full_size_offset);
	if (full_size_offset + sizeof(settings_full_size) +
	    settings_full_size != mmap_size) {
		*error_r = t_strdup_printf("Full size mismatch: "
			"Expected %zu + %zu + %"PRIu64", but file size is %zu",
			full_size_offset, sizeof(settings_full_size),
			settings_full_size, mmap_size);
		return -1;
	}

	uoff_t offset = full_size_offset + sizeof(settings_full_size);
	do {
		if (settings_block_read(mmap, &offset,
					&protocols, error_r) < 0)
			return -1;
	} while (offset < mmap_size);

	if (array_count(&protocols) > 0) {
		array_append_zero(&protocols);
		*specific_services_r = array_front(&protocols);
	} else {
		*specific_services_r = NULL;
	}
	return 0;
}

static int
settings_mmap_apply_blob(struct settings_mmap *mmap,
			 struct setting_parser_context *parser,
			 size_t start_offset, size_t end_offset,
			 const char **error_r)
{
	size_t offset = start_offset;

	/* list of settings: key, value, ... */
	while (offset < end_offset) {
		/* We already checked that settings blob ends with NUL, so
		   strlen() can be used safely. */
		const char *key = (const char *)mmap->mmap_base + offset;
		offset += strlen(key)+1;
		if (offset >= end_offset) {
			/* if offset==end_offset, the value is missing. */
			*error_r = t_strdup_printf(
				"Settings key/value points outside blob "
				"(offset=%zu, end_offset=%zu, file_size=%zu)",
				offset, end_offset, mmap->mmap_size);
			return -1;
		}
		const char *value = (const char *)mmap->mmap_base + offset;
		offset += strlen(value)+1;
		if (offset > end_offset) {
			*error_r = t_strdup_printf(
				"Settings value points outside blob "
				"(offset=%zu, end_offset=%zu, file_size=%zu)",
				offset, end_offset, mmap->mmap_size);
			return -1;
		}
		int ret;
		T_BEGIN {
			/* value points to mmap()ed memory, which is kept
			   referenced by the set_pool for the life time of the
			   settings struct. */
			ret = settings_parse_keyvalue_nodup(parser, key, value);
			if (ret < 0)
				*error_r = t_strdup(settings_parser_get_error(parser));
		} T_END_PASS_STR_IF(ret < 0, error_r);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static int
settings_mmap_apply(struct settings_mmap *mmap, struct event *event,
		    struct setting_parser_context *parser,
		    const struct setting_parser_info *info,
		    const char *filter_name, const char **error_r)
{
	struct settings_mmap_block *block =
		hash_table_lookup(mmap->blocks, info->name);
	if (block == NULL) {
		*error_r = t_strdup_printf(
			"BUG: Configuration has no settings struct named '%s'",
			info->name);
		return -1;
	}
	if (block->error != NULL) {
		*error_r = block->error;
		return -1;
	}

	if (settings_mmap_apply_blob(mmap, parser,
				     block->base_start_offset,
				     block->base_end_offset, error_r) < 0)
		return -1;

	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	if (!array_is_created(&block->filters))
		return 0;

	bool seen_filter = FALSE;
	const struct settings_mmap_filter *config_filter;
	array_foreach(&block->filters, config_filter) {
		if (config_filter->empty_filter ||
		    event_filter_match(config_filter->filter, event,
				       &failure_ctx)) {
			if (config_filter->error != NULL) {
				*error_r = config_filter->error;
				return -1;
			}
			if (filter_name != NULL && !seen_filter) {
				const char *value =
					event_filter_find_field_exact(
						config_filter->filter,
						SETTINGS_EVENT_FILTER_NAME);
				/* NOTE: The event filter is using
				   EVENT_FIELD_EXACT, so the value has already
				   removed wildcard escapes. */
				if (value != NULL &&
				    strcmp(filter_name, value) == 0)
					seen_filter = TRUE;
			}
			if (settings_mmap_apply_blob(mmap, parser,
					config_filter->start_offset,
					config_filter->end_offset,
					error_r) < 0)
				return -1;
		}
	}
	return seen_filter ? 1 : 0;

}

static void settings_mmap_ref(struct settings_mmap *mmap)
{
	i_assert(mmap->refcount > 0);

	mmap->refcount++;
}

static void settings_mmap_unref(struct settings_mmap **_mmap)
{
	struct settings_mmap *mmap = *_mmap;
	if (mmap == NULL)
		return;
	i_assert(mmap->refcount > 0);

	*_mmap = NULL;
	if (--mmap->refcount > 0)
		return;

	settings_mmap_free_blocks(mmap);
	hash_table_destroy(&mmap->blocks);

	if (munmap(mmap->mmap_base, mmap->mmap_size) < 0)
		i_error("munmap(<config>) failed: %m");
	i_free(mmap);
}

int settings_read(struct settings_root *root, int fd, const char *path,
		  const char *protocol_name,
		  const char *const **specific_services_r,
		  const char **error_r)
{
	struct settings_mmap *mmap = i_new(struct settings_mmap, 1);
	mmap->refcount = 1;
	mmap->mmap_base = mmap_ro_file(fd, &mmap->mmap_size);
	if (mmap->mmap_base == MAP_FAILED)
		i_fatal("Failed to read config: mmap(%s) failed: %m", path);
	if (mmap->mmap_size == 0)
		i_fatal("Failed to read config: %s file size is empty", path);
	/* Remember the protocol for following settings lookups */
	root->protocol_name = p_strdup(root->pool, protocol_name);

	settings_mmap_unref(&root->mmap);
	mmap->root = root;
	root->mmap = mmap;
	hash_table_create(&mmap->blocks, default_pool, 0, str_hash, strcmp);

	return settings_mmap_parse(root->mmap, specific_services_r, error_r);
}

bool settings_has_mmap(struct settings_root *root)
{
	return root->mmap != NULL;
}

struct settings_mmap_pool {
	struct pool pool;
	int refcount;

	struct settings_mmap_pool *prev, *next;

	const char *source_filename;
	unsigned int source_linenum;

	pool_t parent_pool;
	struct settings_mmap *mmap; /* NULL for unit tests */
	struct settings_root *root;
};

static const char *settings_mmap_pool_get_name(pool_t pool)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	return pool_get_name(mpool->parent_pool);
}

static void settings_mmap_pool_ref(pool_t pool)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	i_assert(mpool->refcount > 0);
	mpool->refcount++;
}

static void settings_mmap_pool_unref(pool_t *pool)
{
	struct settings_mmap_pool *mpool =
		container_of(*pool, struct settings_mmap_pool, pool);

	i_assert(mpool->refcount > 0);
	*pool = NULL;
	if (--mpool->refcount > 0)
		return;

	DLLIST_REMOVE(&mpool->root->settings_pools, mpool);

	settings_mmap_unref(&mpool->mmap);
	pool_external_refs_unref(&mpool->pool);
	pool_unref(&mpool->parent_pool);
}

static void *settings_mmap_pool_malloc(pool_t pool, size_t size)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	return p_malloc(mpool->parent_pool, size);
}

static void settings_mmap_pool_free(pool_t pool, void *mem)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	p_free(mpool->parent_pool, mem);
}

static void *settings_mmap_pool_realloc(pool_t pool, void *mem,
					size_t old_size, size_t new_size)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	return p_realloc(mpool->parent_pool, mem, old_size, new_size);
}

static void settings_mmap_pool_clear(pool_t pool ATTR_UNUSED)
{
	i_panic("settings_mmap_pool_clear() must not be called");
}

static size_t settings_mmap_pool_get_max_easy_alloc_size(pool_t pool)
{
	struct settings_mmap_pool *mpool =
		container_of(pool, struct settings_mmap_pool, pool);

	return p_get_max_easy_alloc_size(mpool->parent_pool);
}

static struct pool_vfuncs static_settings_mmap_pool_vfuncs = {
	settings_mmap_pool_get_name,

	settings_mmap_pool_ref,
	settings_mmap_pool_unref,

	settings_mmap_pool_malloc,
	settings_mmap_pool_free,

	settings_mmap_pool_realloc,

	settings_mmap_pool_clear,
	settings_mmap_pool_get_max_easy_alloc_size
};

static struct settings_mmap_pool *
settings_mmap_pool_create(struct settings_root *root,
			  struct settings_mmap *mmap,
			  const char *source_filename,
			  unsigned int source_linenum)
{
	struct settings_mmap_pool *mpool;
	pool_t parent_pool =
		pool_alloconly_create("settings mmap", 256);

	mpool = p_new(parent_pool, struct settings_mmap_pool, 1);
	mpool->pool.v = &static_settings_mmap_pool_vfuncs;
	mpool->pool.alloconly_pool = TRUE;
	mpool->refcount = 1;
	mpool->parent_pool = parent_pool;
	mpool->root = root;
	mpool->mmap = mmap;
	mpool->source_filename = source_filename;
	mpool->source_linenum = source_linenum;
	if (mmap != NULL)
		settings_mmap_ref(mmap);

	DLLIST_PREPEND(&root->settings_pools, mpool);
	return mpool;
}

static void
settings_var_expand_init(struct event *event,
			 const struct var_expand_table **tab_r,
			 const struct var_expand_func_table **func_tab_r,
			 void **func_context_r)
{
	*tab_r = NULL;
	*func_tab_r = NULL;

	while (event != NULL) {
		settings_var_expand_t *callback =
			event_get_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK);
		if (callback != NULL) {
			callback(event, tab_r, func_tab_r);
			break;
		}

		*tab_r = event_get_ptr(event, SETTINGS_EVENT_VAR_EXPAND_TABLE);
		*func_tab_r = event_get_ptr(event, SETTINGS_EVENT_VAR_EXPAND_FUNC_TABLE);
		if (*tab_r != NULL || *func_tab_r != NULL)
			break;
		event = event_get_parent(event);
	}
	if (*tab_r == NULL)
		*tab_r = t_new(struct var_expand_table, 1);
	*func_context_r = event == NULL ? NULL :
		event_get_ptr(event, SETTINGS_EVENT_VAR_EXPAND_FUNC_CONTEXT);
}

static int settings_override_cmp(const struct settings_override *set1,
				 const struct settings_override *set2)
{
	return set1->type - set2->type;
}

static int
settings_override_get_value(struct setting_parser_context *parser,
			    const struct settings_override *set,
			    const char **_key, const char **value_r,
			    const char **error_r)
{
	const char *key = *_key;
	enum setting_type value_type;
	const void *old_value = NULL;
	if (set->last_filter_value != NULL) {
		/* Try filter/name/key -> filter_key. Do this before the
		   non-prefixed check, so e.g. inet_listener/imap/ssl won't
		   try to change the global ssl setting. */
		const char *key_prefix = set->last_filter_key;
		if (strcmp(key_prefix, SETTINGS_EVENT_MAILBOX_NAME_WITHOUT_PREFIX) == 0)
			key_prefix = SETTINGS_EVENT_MAILBOX_NAME_WITH_PREFIX;
		const char *prefixed_key =
			t_strdup_printf("%s_%s", key_prefix, key);
		old_value = settings_parse_get_value(parser, &prefixed_key, &value_type);
		if (old_value != NULL)
			key = prefixed_key;
	}
	if (old_value == NULL)
		old_value = settings_parse_get_value(parser, &key, &value_type);
	if (old_value == NULL && !str_begins_with(key, "plugin/") &&
	    set->type == SETTINGS_OVERRIDE_TYPE_USERDB) {
		/* FIXME: Setting is unknown in this parser. Since the parser
		   doesn't know all settings, we can't be sure if it's because
		   it should simply be ignored or because it's a plugin setting.
		   Just assume it's a plugin setting for now. This code will get
		   removed eventually once all plugin settings have been
		   converted away. */
		key = t_strconcat("plugin/", key, NULL);
		old_value = settings_parse_get_value(parser, &key, &value_type);
	}
	if (!set->append || old_value == NULL) {
		*_key = key;
		*value_r = set->value;
		return 1;
	}

	if (value_type != SET_STR) {
		*error_r = t_strdup_printf(
			"%s setting is not a string - can't use '+'", key);
		return -1;
	}
	const char *const *strp = old_value;
	*_key = key;
	*value_r = t_strconcat(*strp, set->value, NULL);
	return 1;
}

static int
settings_instance_override(struct settings_root *root,
			   struct settings_instance *instance,
			   struct setting_parser_context *parser,
			   struct settings_mmap_pool *mpool,
			   struct event *event,
			   const char *filter_key, const char *filter_value,
			   const char **error_r)
{
	ARRAY_TYPE(settings_override) overrides;

	t_array_init(&overrides, 64);
	if (array_is_created(&instance->overrides))
		array_append_array(&overrides, &instance->overrides);
	if (array_is_created(&root->overrides))
		array_append_array(&overrides, &root->overrides);
	array_sort(&overrides, settings_override_cmp);

	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	bool seen_filter = FALSE;
	const struct settings_override *set;
	array_foreach(&overrides, set) {
		const char *key = set->key, *value;

		if (set->filter != NULL &&
		    !event_filter_match(set->filter, event, &failure_ctx))
			continue;

		if (filter_key != NULL && set->last_filter_key != NULL &&
		    strcmp(filter_key, set->last_filter_key) == 0 &&
		    null_strcmp(filter_value, set->last_filter_value) == 0)
			seen_filter = TRUE;

		int ret = settings_override_get_value(parser, set,
						      &key, &value, error_r);
		if (ret < 0)
			return -1;
		if (ret == 0)
			continue;

		if (value != set->value)
			ret = settings_parse_keyvalue(parser, key, value);
		else {
			/* Add explicit reference to instance->pool, which is
			   kept by the settings struct's pool. This allows
			   settings to survive even if the instance is freed.

			   If there is no instance pool, it means there are
			   only CLI_PARAM settings, which are allocated from
			   FIXME: should figure out some efficient way how to
			   store them. */
			if (array_is_created(&mpool->pool.external_refs))
				i_assert(array_idx_elem(&mpool->pool.external_refs, 0) == instance->pool);
			else if (instance->pool != NULL)
				pool_add_external_ref(&mpool->pool, instance->pool);
			ret = settings_parse_keyvalue_nodup(parser, key, value);
		}
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to override configuration from %s: "
				"Invalid %s=%s: %s",
				settings_override_type_names[set->type],
				key, value, settings_parser_get_error(parser));
			return -1;
		}
	}
	return seen_filter ? 1 : 0;
}

static int
settings_instance_get(struct event *event,
		      struct settings_root *root,
		      struct settings_instance *instance,
		      const char *filter_key, const char *filter_value,
		      const char *filter_name,
		      const struct setting_parser_info *info,
		      enum settings_get_flags flags,
		      const char *source_filename,
		      unsigned int source_linenum,
		      const void **set_r, const char **error_r)
{
	const char *error;
	bool seen_filter = FALSE;
	int ret;

	i_assert(info->pool_offset1 != 0);

	*set_r = NULL;

	event = event_create(event);
	if (filter_name != NULL)
		event_add_str(event, SETTINGS_EVENT_FILTER_NAME, filter_name);
	if (event_find_field_recursive(event, "protocol") == NULL)
		event_add_str(event, "protocol", root->protocol_name);

	struct settings_mmap_pool *mpool =
		settings_mmap_pool_create(root, instance->mmap,
					  source_filename, source_linenum);
	pool_t set_pool = &mpool->pool;
	struct setting_parser_context *parser =
		settings_parser_init(set_pool, info,
				     SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (instance->mmap != NULL) {
		ret = settings_mmap_apply(instance->mmap, event, parser, info,
					  filter_name, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to parse configuration: %s", error);
			settings_parser_unref(&parser);
			pool_unref(&set_pool);
			event_unref(&event);
			return -1;
		}
		if (ret > 0)
			seen_filter = TRUE;
	}

	/* if we change any settings afterwards, they're in expanded form.
	   especially all settings from userdb are already expanded. */
	settings_parse_set_expanded(parser, TRUE);

	T_BEGIN {
		ret = settings_instance_override(root, instance, parser, mpool,
			event, filter_key, filter_value, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0) {
		settings_parser_unref(&parser);
		pool_unref(&set_pool);
		event_unref(&event);
		return -1;
	}
	if (ret > 0)
		seen_filter = TRUE;

	void *set = settings_parser_get_set(parser);

	pool_t *pool_p = PTR_OFFSET(set, info->pool_offset1 - 1);
	*pool_p = set_pool;

	/* settings are now referenced, but the parser is no longer needed */
	settings_parser_unref(&parser);

	if (filter_key != NULL && !seen_filter) {
		pool_unref(&set_pool);
		event_unref(&event);
		return 0;
	}
	if ((flags & SETTINGS_GET_FLAG_NO_CHECK) == 0) {
		if (!settings_check(event, info, *pool_p, set, error_r)) {
			*error_r = t_strdup_printf("Invalid %s settings: %s",
						   info->name, *error_r);
			pool_unref(&set_pool);
			event_unref(&event);
			return -1;
		}
	}

	if ((flags & SETTINGS_GET_FLAG_NO_EXPAND) != 0)
		ret = 1;
	else if ((flags & SETTINGS_GET_FLAG_FAKE_EXPAND) != 0) {
		settings_var_skip(info, set);
		ret = 1;
	} else T_BEGIN {
		const struct var_expand_table *tab;
		const struct var_expand_func_table *func_tab;
		void *func_context;

		settings_var_expand_init(event, &tab, &func_tab, &func_context);
		ret = settings_var_expand_with_funcs(info, set, *pool_p, tab,
						     func_tab, func_context,
						     error_r);
	} T_END_PASS_STR_IF(ret <= 0, error_r);
	if (ret <= 0) {
		*error_r = t_strdup_printf(
			"Failed to expand %s setting variables: %s",
			info->name, *error_r);
		pool_unref(&set_pool);
		event_unref(&event);
		return -1;
	}

	*set_r = set;
	event_unref(&event);
	return 1;
}

static int
settings_get_full(struct event *event,
		  const char *filter_key, const char *filter_value,
		  const struct setting_parser_info *info,
		  enum settings_get_flags flags,
		  const char *source_filename,
		  unsigned int source_linenum,
		  const void **set_r, const char **error_r)
{
	struct settings_root *root = NULL;
	struct settings_mmap *mmap = NULL;
	struct settings_instance *instance = NULL;
	struct event *scan_event = event;

	i_assert((filter_key == NULL) == (filter_value == NULL));

	do {
		if (root == NULL)
			root = event_get_ptr(scan_event, SETTINGS_EVENT_ROOT);
		if (instance == NULL) {
			instance = event_get_ptr(scan_event,
						 SETTINGS_EVENT_INSTANCE);
		}
		if (filter_key == NULL) {
			filter_key = event_get_ptr(scan_event,
						   SETTINGS_EVENT_FILTER_NAME);
		}
		if (root != NULL && instance != NULL && filter_key != NULL)
			break;
		scan_event = event_get_parent(scan_event);
	} while (scan_event != NULL);

	if (root == NULL)
		i_panic("settings_get() - event has no SETTINGS_EVENT_ROOT");
	if (instance != NULL)
		mmap = instance->mmap;
	else
		mmap = root->mmap;

	/* no instance-specific settings */
	struct settings_instance empty_instance = {
		.mmap = mmap,
	};
	if (instance == NULL)
		instance = &empty_instance;

	const char *filter_name;
	if (filter_value != NULL) {
		filter_name = t_strdup_printf("%s/%s", filter_key,
			settings_section_escape(filter_value));
	} else if (filter_key != NULL)
		filter_name = filter_key;
	else
		filter_name = NULL;

	return settings_instance_get(event, root, instance,
		filter_key, filter_value, filter_name, info, flags,
		source_filename, source_linenum, set_r, error_r);
}

#undef settings_get
int settings_get(struct event *event,
		 const struct setting_parser_info *info,
		 enum settings_get_flags flags,
		 const char *source_filename,
		 unsigned int source_linenum,
		 const void **set_r, const char **error_r)
{
	int ret = settings_get_full(event, NULL, NULL, info, flags,
				    source_filename, source_linenum,
				    set_r, error_r);
	i_assert(ret != 0);
	return ret < 0 ? -1 : 0;
}

#undef settings_get_filter
int settings_get_filter(struct event *event,
			const char *filter_key, const char *filter_value,
			const struct setting_parser_info *info,
			enum settings_get_flags flags,
			const char *source_filename,
			unsigned int source_linenum,
			const void **set_r, const char **error_r)
{
	int ret = settings_get_full(event, filter_key, filter_value, info,
				    flags, source_filename, source_linenum,
				    set_r, error_r);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		/* e.g. namespace=foo was given but no namespace/foo/name */
		*error_r = t_strdup_printf(
			"Filter %s=%s unexpectedly not found "
			"(invalid userdb or -o override settings?)",
			filter_key, filter_value);
		return -1;
	}
	return 0;
}

#undef settings_try_get_filter
int settings_try_get_filter(struct event *event,
			    const char *filter_key, const char *filter_value,
			    const struct setting_parser_info *info,
			    enum settings_get_flags flags,
			    const char *source_filename,
			    unsigned int source_linenum,
			    const void **set_r, const char **error_r)
{
	return settings_get_full(event, filter_key, filter_value, info,
				 flags, source_filename, source_linenum,
				 set_r, error_r);
}

#undef settings_get_or_fatal
const void *
settings_get_or_fatal(struct event *event,
		      const struct setting_parser_info *info,
		      const char *source_filename,
		      unsigned int source_linenum)
{
	const void *set;
	const char *error;

	if (settings_get(event, info, 0, source_filename,
			 source_linenum, &set, &error) < 0)
		i_fatal("%s", error);
	return set;
}

static void
settings_override_get_filter(struct settings_override *set, pool_t pool,
			     const char *_key)
{
	const char *key = _key;
	const char *error;

	/* key could be e.g.:
	   - global: dict_driver=file
	   - accessed via named filter: mail_attribute_dict/dict_driver=file
	   - inside multiple filters:
	     namespace/inbox/mailbox/Trash/dict_driver=file
	   - named filter inside multiple filters:
	     namespace/inbox/mailbox/Trash/mail_attribute_dict/dict_driver=file

	   We start by converting all key/value/ prefixes to key=value in
	   event filter. At the end there are 0..1 '/' characters left.
	*/
	const char *last_filter_key = NULL, *last_filter_value = NULL;
	const char *value, *next;
	string_t *filter = NULL;
	size_t last_filter_key_pos = 0;
	while ((value = strchr(key, '/')) != NULL &&
	       (next = strchr(value + 1, '/')) != NULL) {
		if (filter == NULL)
			filter = t_str_new(64);
		else
			str_append(filter, " AND ");

		last_filter_key = t_strdup_until(key, value);
		if (strcmp(last_filter_key, SETTINGS_EVENT_MAILBOX_NAME_WITH_PREFIX) == 0)
			last_filter_key = SETTINGS_EVENT_MAILBOX_NAME_WITHOUT_PREFIX;
		last_filter_value = t_strdup_until(value + 1, next);
		last_filter_key_pos = str_len(filter);
		str_printfa(filter, "\"%s\"=\"%s\"",
			    wildcard_str_escape(last_filter_key),
			    str_escape(last_filter_value));
		key = next + 1;
	}
	if (value != NULL && !str_begins_with(key, "plugin")) {
		/* There is one more '/' left - this is a named filter e.g.
		   mail_attribute_dict/dict_driver=file */
		set->last_filter_key = p_strdup_until(pool, key, value);
		set->last_filter_value = NULL;
		if (filter == NULL)
			filter = t_str_new(64);
		else
			str_append(filter, " AND ");
		str_printfa(filter, SETTINGS_EVENT_FILTER_NAME"=\"%s\"",
			    wildcard_str_escape(set->last_filter_key));
		key = value + 1;
	} else if (last_filter_key != NULL) {
		str_insert(filter, last_filter_key_pos, "(");
		str_printfa(filter, " OR "SETTINGS_EVENT_FILTER_NAME"=\"%s/%s\")",
			    last_filter_key, wildcard_str_escape(
				settings_section_escape(last_filter_value)));
		set->last_filter_key = p_strdup(pool, last_filter_key);
		set->last_filter_value = p_strdup(pool, last_filter_value);
	}
	set->key = p_strdup(pool, key);

	if (filter == NULL)
		return;

	set->filter = event_filter_create();
	if (event_filter_parse_case_sensitive(str_c(filter), set->filter,
					      &error) < 0) {
		i_panic("BUG: Failed to create event filter filter for %s: %s",
			_key, error);
	}
}

void settings_override(struct settings_instance *instance,
		       const char *key, const char *value,
		       enum settings_override_type type)
{
	if (!array_is_created(&instance->overrides))
		p_array_init(&instance->overrides, instance->pool, 16);
	struct settings_override *set =
		array_append_space(&instance->overrides);
	set->type = type;
	size_t len = strlen(key);
	T_BEGIN {
		if (len > 0 && key[len-1] == '+') {
			/* key+=value */
			set->append = TRUE;
			key = t_strndup(key, len-1);
		}
		set->value = p_strdup(instance->pool, value);
		settings_override_get_filter(set, instance->pool, key);
	} T_END;
}

void settings_root_override(struct settings_root *root,
			    const char *key, const char *value,
			    enum settings_override_type type)
{
	if (!array_is_created(&root->overrides))
		p_array_init(&root->overrides, root->pool, 16);
	struct settings_override *set =
		array_append_space(&root->overrides);
	set->type = type;
	set->value = p_strdup(root->pool, value);
	T_BEGIN {
		settings_override_get_filter(set, root->pool, key);
	} T_END;
}

static struct settings_instance *
settings_instance_alloc(void)
{
	pool_t pool = pool_alloconly_create("settings instance", 1024);
	struct settings_instance *instance =
		p_new(pool, struct settings_instance, 1);
	instance->pool = pool;
	return instance;
}

struct settings_instance *
settings_instance_new(struct settings_root *root)
{
	struct settings_instance *instance = settings_instance_alloc();
	instance->mmap = root->mmap;
	return instance;
}

struct settings_instance *
settings_instance_dup(const struct settings_instance *src)
{
	struct settings_instance *dest = settings_instance_alloc();
	dest->mmap = src->mmap;

	if (!array_is_created(&src->overrides))
		return dest;

	p_array_init(&dest->overrides, dest->pool,
		     array_count(&src->overrides) + 8);
	const struct settings_override *src_set;
	array_foreach(&src->overrides, src_set) {
		struct settings_override *dest_set =
			array_append_space(&dest->overrides);
		dest_set->type = src_set->type;
		dest_set->append = src_set->append;
		dest_set->key = p_strdup(dest->pool, src_set->key);
		dest_set->value = p_strdup(dest->pool, src_set->value);
	}
	return dest;
}

void settings_instance_free(struct settings_instance **_instance)
{
	struct settings_instance *instance = *_instance;
	struct settings_override *override;

	*_instance = NULL;

	if (array_is_created(&instance->overrides)) {
		array_foreach_modifiable(&instance->overrides, override)
			event_filter_unref(&override->filter);
	}
	pool_unref(&instance->pool);
}

struct settings_root *settings_root_init(void)
{
	pool_t pool = pool_alloconly_create("settings root", 128);
	struct settings_root *root = p_new(pool, struct settings_root, 1);
	root->pool = pool;
	return root;
}

void settings_root_deinit(struct settings_root **_root)
{
	struct settings_root *root = *_root;
	struct settings_override *override;
	struct settings_mmap_pool *mpool;

	*_root = NULL;

	if (array_is_created(&root->overrides)) {
		array_foreach_modifiable(&root->overrides, override)
			event_filter_unref(&override->filter);
	}
	settings_mmap_unref(&root->mmap);

	for (mpool = root->settings_pools; mpool != NULL; mpool = mpool->next) {
		i_warning("Leaked settings: %s:%u",
			  mpool->source_filename, mpool->source_linenum);
	}
	pool_unref(&root->pool);
}
