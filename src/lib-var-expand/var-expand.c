/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "cpu-count.h"
#include "guid.h"
#include "hostpid.h"
#include "str.h"
#include "time-util.h"
#include "var-expand-private.h"
#include "var-expand-parser.h"
#include "expansion.h"
#include "dovecot-version.h"

#include <unistd.h>
#include <stdint.h>
#include <time.h>

#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

#define ENV_CPU_COUNT "NCPU"
enum os_default_type {
	OS_DEFAULT_TYPE_SYSNAME,
	OS_DEFAULT_TYPE_RELEASE,
};

const void *const var_expand_contexts_end = POINTER_CAST(UINTPTR_MAX);

static int
var_expand_process(const char *field, const char **result_r,
		   void *context ATTR_UNUSED, const char **error_r)
{
	if (strcmp(field, "pid") == 0)
		*result_r = my_pid;
	else if (strcmp(field, "uid") == 0)
		*result_r = dec2str(geteuid());
	else if (strcmp(field, "gid") == 0)
		*result_r = dec2str(getegid());
	else {
		*error_r = t_strdup_printf("Unsupported field '%s'",
					   field);
		return -1;
	}
	return 0;
}

static struct utsname utsname_result;
static bool utsname_set = FALSE;

static int
var_expand_system_os(enum os_default_type type,
		     const char **value_r, const char **error_r)
{
	if (!utsname_set) {
		utsname_set = TRUE;

		if (uname(&utsname_result) < 0) {
			*error_r = t_strdup_printf("uname() failed: %m");
			i_zero(&utsname_result);
			return -1;
		}
	}

	switch (type) {
	case OS_DEFAULT_TYPE_SYSNAME:
		*value_r = utsname_result.sysname;
		return 0;
	case OS_DEFAULT_TYPE_RELEASE:
		*value_r = utsname_result.release;
		return 0;
	default:
		break;
	}

	i_unreached();
}

static int
var_expand_system(const char *field, const char **result_r,
		  void *context ATTR_UNUSED, const char **error_r)
{
	if (strcmp(field, "cpu_count") == 0) {
		int ncpus;
		const char *cpuenv = getenv(ENV_CPU_COUNT);
		if (cpuenv != NULL) {
			*result_r = cpuenv;
			return 0;
		}
		if (cpu_count_get(&ncpus, error_r) < 0)
			return -1;
		*result_r = dec2str(ncpus);
		return 0;
	} else if (strcmp(field, "hostname") == 0) {
		*result_r = my_hostname;
		return 0;
	} else if (strcmp(field, "os") == 0)
		return var_expand_system_os(OS_DEFAULT_TYPE_SYSNAME, result_r,
					    error_r);
	else if (strcmp(field, "os-version") == 0)
		return var_expand_system_os(OS_DEFAULT_TYPE_RELEASE, result_r,
					    error_r);
	*error_r = t_strdup_printf("Unsupported field '%s'", field);
	return -1;
}

static int
var_expand_dovecot(const char *field, const char **result_r,
		   void *context ATTR_UNUSED, const char **error_r)
{
	if (strcmp(field, "name") == 0) {
		*result_r = PACKAGE_NAME;
		return 0;
	} else if (strcmp(field, "version") == 0) {
		*result_r = PACKAGE_VERSION;
		return 0;
	} else if (strcmp(field, "support-url") == 0) {
		*result_r = PACKAGE_WEBPAGE;
		return 0;
	} else if (strcmp(field, "support-email") == 0) {
		*result_r = PACKAGE_BUGREPORT;
		return 0;
	} else if (strcmp(field, "revision") == 0) {
		*result_r = DOVECOT_REVISION;
		return 0;
	}

	*error_r = t_strdup_printf("Unsupported field '%s'", field);
	return -1;
}

static int var_expand_env(const char *key, const char **value_r,
			  void *context ATTR_UNUSED, const char **error_r)
{
	if (*key == '\0') {
		*error_r = "Missing field";
		return -1;
	}

	const char *value = getenv(key);

	/* never fail with env, it would make code too hard */
	if (value == NULL)
		value = "";

	*value_r = value;
	return 0;
}

static int var_expand_event(const char *key, const char **value_r, void *context,
			    const char **error_r)
{
	const struct var_expand_params *params = context;
	struct event *event = params->event;

	if (event == NULL)
		event = event_get_global();
	if (event == NULL) {
		*error_r = "No event available";
		return -1;
	}

	const char *value = event_find_field_recursive_str(event, key);

	if (value == NULL) {
		*error_r = t_strdup_printf("No such field '%s' in event", key);
		return -1;
	}

	*value_r = value;

	return 0;
}

static int var_expand_date(const char *key, const char **value_r,
			   void *context ATTR_UNUSED, const char **error_r)
{
	struct tm tm;
	struct timeval tv;
	i_gettimeofday(&tv);
	if (unlikely(localtime_r(&tv.tv_sec, &tm) == NULL))
		i_panic("localtime_r() failed: %m");

	if (strcmp(key, "year") == 0)
		*value_r = t_strftime("%Y", &tm);
	else if (strcmp(key, "month") == 0)
		*value_r = t_strftime("%m", &tm);
	else if (strcmp(key, "day") == 0)
		*value_r = t_strftime("%d", &tm);
	else
		ERROR_UNSUPPORTED_KEY(key);
	return 0;
}

static int var_expand_time(const char *key, const char **value_r,
			   void *context ATTR_UNUSED, const char **error_r)
{
	struct tm tm;
	struct timeval tv;
	i_gettimeofday(&tv);
	if (unlikely(localtime_r(&tv.tv_sec, &tm) == NULL))
		i_panic("localtime_r() failed: %m");

	if (strcmp(key, "hour") == 0)
		*value_r = t_strftime("%H", &tm);
	else if (strcmp(key, "min") == 0 ||
		 strcmp(key, "minute") == 0)
		*value_r = t_strftime("%M", &tm);
	else if (strcmp(key, "sec") == 0 ||
		 strcmp(key, "second") == 0)
		*value_r = t_strftime("%S", &tm);
	else if (strcmp(key, "us") == 0 ||
		 strcmp(key, "usec") == 0)
		*value_r = dec2str(tv.tv_usec);
	else
		ERROR_UNSUPPORTED_KEY(key);
	return 0;
}

static int var_expand_generate(const char *key, const char **value_r,
			       void *context ATTR_UNUSED, const char **error_r)
{
	guid_128_t guid;

	if (strcmp(key, "guid") == 0) {
		*value_r = guid_generate();
		return 0;
	}
	if (strcmp(key, "guid128") == 0) {
		guid_128_generate(guid);
		*value_r = guid_128_to_string(guid);
		return 0;
	}
	if (str_begins(key, "uuid", &key)) {
		guid_128_uuid4_generate(guid);
		if (key[0] == '\0' || strcmp(key, ":record") == 0)
			*value_r = guid_128_to_uuid_string(guid, FORMAT_RECORD);
		else if (strcmp(key, ":compact") == 0)
			*value_r = guid_128_to_uuid_string(guid, FORMAT_COMPACT);
		else if (strcmp(key, ":microsoft") == 0)
			*value_r = guid_128_to_uuid_string(guid, FORMAT_MICROSOFT);
		else
			ERROR_UNSUPPORTED_KEY(key);
		return 0;
	}
	ERROR_UNSUPPORTED_KEY(key);
}

static const struct var_expand_provider internal_providers[] = {
	{ .key = "process", .func = var_expand_process },
	{ .key = "system", .func = var_expand_system  },
	{ .key = "dovecot", .func = var_expand_dovecot  },
	{ .key = "env", .func = var_expand_env },
	{ .key = "event", .func = var_expand_event },
	{ .key = "date", .func = var_expand_date },
	{ .key = "time", .func = var_expand_time },
	{ .key = "generate", .func = var_expand_generate },
	VAR_EXPAND_TABLE_END
};

bool var_expand_provider_is_builtin(const char *prefix)
{
	for (size_t i = 0; internal_providers[i].key != NULL; i++)
		if (strcmp(prefix, internal_providers[i].key) == 0)
			return TRUE;
	return FALSE;
}

static int var_expand_table_key_cmp(const char *key,
				    const struct var_expand_table *elem)
{
	return strcmp(key, elem->key);
}

struct var_expand_table *
var_expand_merge_tables(pool_t pool, const struct var_expand_table *a,
			    const struct var_expand_table *b)
{
	ARRAY(struct var_expand_table) table;
	size_t a_size = var_expand_table_size(a);
	size_t b_size = var_expand_table_size(b);
	p_array_init(&table, pool, a_size + b_size + 1);
	for (size_t i = 0; i < a_size; i++) {
		struct var_expand_table *entry =
			array_append_space(&table);
		entry->value = p_strdup(pool, a[i].value);
		entry->key = p_strdup(pool, a[i].key);
	}
	for (size_t i = 0; i < b_size; i++) {
		/* check if it's there first */
		struct var_expand_table *entry =
			array_lsearch_modifiable(&table, b[i].key,
						 var_expand_table_key_cmp);
		if (entry != NULL) {
			entry->value = b->value;
			continue;
		}

		entry = array_append_space(&table);
		entry->value = p_strdup(pool, b[i].value);
		entry->key = p_strdup(pool, b[i].key);
	}
	array_append_zero(&table);
	return array_front_modifiable(&table);
}

void var_expand_state_set_transfer_data(struct var_expand_state *state,
					const void *value, size_t len)
{
	/* Ensure we are not using value from transfer data */
	i_assert((const char *)value < (const char *)state->transfer->data ||
		 (const char *)value > (const char *)state->transfer->data +
						     state->transfer->used);
	str_truncate(state->transfer, 0);
	str_append_data(state->transfer, value, len);
	state->transfer_set = TRUE;
}

void var_expand_state_set_transfer_binary(struct var_expand_state *state,
					  const void *value, size_t len)
{
	var_expand_state_set_transfer_data(state, value, len);
	state->transfer_binary = TRUE;
}

void var_expand_state_set_transfer(struct var_expand_state *state, const char *value)
{
	size_t len;
	if (value == NULL)
		len = 0;
	else
		len = strlen(value);
	var_expand_state_set_transfer_data(state, value, len);
	state->transfer_binary = FALSE;
}

void var_expand_state_unset_transfer(struct var_expand_state *state)
{
	str_truncate(state->transfer, 0);
	state->transfer_set = FALSE;
}

static int call_provider_table(const struct var_expand_provider *prov,
			       void *prov_context,
			       const char *prefix, const char *key,
			       const char **value_r, bool *found_r,
			       const char **error_r)
{
	i_assert(prov_context != var_expand_contexts_end);
	for (; prov != NULL && prov->key != NULL; prov++) {
		if (strcmp(prov->key, prefix) == 0) {
			*found_r = TRUE;
			return prov->func(key, value_r, prov_context, error_r);
		}
	}
	*found_r = FALSE;
	return -1;
}

static int call_value_provider(const struct var_expand_state *state,
			       const char *prefix, const char *key,
			       const char **value_r, const char **error_r)
{
	bool found;
	int ret = call_provider_table(internal_providers, (void*)state->params, prefix, key, value_r,
				      &found, error_r);
	if (found)
		; /* pass */
	else if (state->params->providers_arr != NULL) {
		void *context = state->params->context;
		void *const *contexts = state->params->contexts;
		for (const struct var_expand_provider *const *prov = state->params->providers_arr;
		     *prov != NULL; prov++) {
			if (contexts != NULL) {
				context = *contexts;
				contexts++;
			}
			ret = call_provider_table(*prov, context, prefix, key, value_r,
						  &found, error_r);
			if (found)
				break;
		}
	} else {
		ret = call_provider_table(state->params->providers,
					  state->params->context,
					  prefix, key, value_r, &found, error_r);
	}

	if (!found) {
		*error_r = t_strdup_printf("Unsupported prefix '%s'", prefix);
		ret = -1;
	} else if (ret == -1) {
		/* Add prefix to errors */
		*error_r = t_strdup_printf("%s: %s", prefix, *error_r);
	}

	i_assert(*value_r != NULL || ret == -1);

	return ret;
}

static int lookup_table(const struct var_expand_table *table,
			void *context, const char *name,
			const char **result_r, bool *found_r, const char **error_r)
{
	i_assert(context != var_expand_contexts_end);
	for (size_t i = 0; table != NULL && table[i].key != NULL; i++) {
		if (strcmp(table[i].key, name) == 0) {
			*found_r = TRUE;
			if (table[i].func != NULL) {
				int ret = table[i].func(name, result_r,
							context, error_r);
				i_assert(ret >= 0 || *error_r != NULL);
				return ret >= 0 ? 0 : -1;
			} else
				*result_r = table[i].value == NULL ? "" : table[i].value;
			return 0;
		}
	};

	*error_r = t_strdup_printf("Unknown variable '%s'", name);
	return -1;
}

static int lookup_tables(const struct var_expand_state *state, const char *name,
			 const char **result_r, const char **error_r)
{
	int ret;
	bool found;

	if (state->params->tables_arr != NULL) {
		void *context = state->params->context;
		void *const *contexts = state->params->contexts;
		for (const struct var_expand_table *const *table = state->params->tables_arr;
		     *table != NULL; table++) {
			if (contexts != NULL) {
				context = *contexts;
				contexts++;
			}
			found = FALSE;
			ret = lookup_table(*table, context, name, result_r, &found, error_r);
			if (found)
				return ret;
		}
		*error_r = t_strdup_printf("Unknown variable '%s'", name);
		return -1;
	}

	return lookup_table(state->params->table, state->params->context,
			    name, result_r, &found, error_r);
}

int var_expand_state_lookup_variable(const struct var_expand_state *state,
				     const char *name, const char **result_r,
				     const char **error_r)
{
	const char *prefix = name;
	name = strchr(name, ':');

	if (name == NULL) {
		name = prefix;
		prefix = NULL;
	} else {
		prefix = t_strdup_until(prefix, name);
		name++;
	}

	if (prefix != NULL) {
		return call_value_provider(state, prefix, name, result_r, error_r);
	} else {
		return lookup_tables(state, name, result_r, error_r);
	}
}

int var_expand(string_t *dest, const char *str,
	       const struct var_expand_params *params,
	       const char **error_r)
{
	struct var_expand_program *program = NULL;
	if (var_expand_program_create(str, &program, error_r) != 0)
		return -1;
	i_assert(program != NULL);
	int ret = var_expand_program_execute(dest, program, params, error_r);
	var_expand_program_free(&program);

	return ret;
}

int t_var_expand(const char *str, const struct var_expand_params *params,
		 const char **result_r, const char **error_r)
{

	string_t *dest = t_str_new(32);
	int ret = var_expand(dest, str, params, error_r);
	if (ret < 0)
		return ret;
	*result_r = str_c(dest);
	return 0;
}
