/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "path-util.h"
#include "module-dir.h"
#include "env-util.h"
#include "guid.h"
#include "hash.h"
#include "hostpid.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "settings-parser.h"
#include "master-interface.h"
#include "master-service.h"
#include "all-settings.h"
#include "sysinfo-get.h"
#include "old-set-parser.h"
#include "config-dump-full.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"
#include "dovecot-version.h"

#include <ctype.h>
#include <unistd.h>
#include <sysexits.h>

struct prefix_stack {
	unsigned int prefix_idx;
};
ARRAY_DEFINE_TYPE(prefix_stack, struct prefix_stack);

struct config_dump_human_context {
	pool_t pool;
	string_t *list_prefix;
	ARRAY_TYPE(const_string) strings;
	struct config_export_context *export_ctx;

	bool list_prefix_sent:1;
};

#define LIST_KEY_PREFIX "\001"

static struct config_parsed *config;
static const char *indent_str = "                              !!!!";

static const char *const secrets[] = {
	"key",
	"secret",
	"pass",
	"http://",
	"https://",
	"ftp://",
	NULL
};


static void
config_request_get_strings(const struct config_export_setting *set,
			   struct config_dump_human_context *ctx)
{
	const char *value;

	switch (set->type) {
	case CONFIG_KEY_NORMAL:
		value = p_strdup_printf(ctx->pool, "%s=%s", set->key, set->value);
		break;
	case CONFIG_KEY_LIST:
		value = p_strdup_printf(ctx->pool, LIST_KEY_PREFIX"%s=%s",
					set->key, set->value);
		break;
	case CONFIG_KEY_FILTER_ARRAY:
		return;
	}
	array_push_back(&ctx->strings, &value);
}

static int config_string_cmp(const char *const *p1, const char *const *p2)
{
	const char *s1 = *p1, *s2 = *p2;
	unsigned int i = 0;

	while (s1[i] == s2[i]) {
		if (s1[i] == '\0' || s1[i] == '=')
			return 0;
		i++;
	}

	if (s1[i] == '=')
		return -1;
	if (s2[i] == '=')
		return 1;

	return (signed char)s1[i] - (signed char)s2[i];
}

static struct prefix_stack prefix_stack_pop(ARRAY_TYPE(prefix_stack) *stack)
{
	const struct prefix_stack *s;
	struct prefix_stack sc;
	unsigned int count;

	s = array_get(stack, &count);
	i_assert(count > 0);
	if (count == 1) {
		sc.prefix_idx = UINT_MAX;
	} else {
		sc.prefix_idx = s[count-2].prefix_idx;
	}
	array_delete(stack, count-1, 1);
	return sc;
}

static struct config_dump_human_context *
config_dump_human_init(enum config_dump_scope scope)
{
	struct config_dump_human_context *ctx;
	enum config_dump_flags flags;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"config human strings", 1024*32);
	ctx = p_new(pool, struct config_dump_human_context, 1);
	ctx->pool = pool;
	ctx->list_prefix = str_new(ctx->pool, 128);
	i_array_init(&ctx->strings, 256);

	flags = CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS;
	ctx->export_ctx = config_export_init(scope, flags,
					     config_request_get_strings, ctx);
	return ctx;
}

static void config_dump_human_deinit(struct config_dump_human_context *ctx)
{
	array_free(&ctx->strings);
	pool_unref(&ctx->pool);
}

static bool value_need_quote(const char *value)
{
	size_t len = strlen(value);

	if (len == 0)
		return FALSE;

	if (strchr(value, '#') != NULL)
		return TRUE;
	if (IS_WHITE(value[0]) || IS_WHITE(value[len-1]))
		return TRUE;
	return FALSE;
}

static const char *find_next_secret(const char *input, const char **secret_r)
{
	const char *const *secret;
	const char *ptr = NULL;
	*secret_r = NULL;
	for(secret = secrets; *secret != NULL; secret++) {
		const char *cptr;
		if ((cptr = strstr(input, *secret)) != NULL) {
			if (ptr == NULL || cptr < ptr) {
				*secret_r = *secret;
				ptr = cptr;
			}
		}
	}
	i_assert(*secret_r != NULL || ptr == NULL);
	return ptr;
}

static bool
hide_url_userpart_from_value(struct ostream *output, const char **_ptr,
			     const char **optr, bool quote)
{
	const char *ptr = *_ptr;
	const char *start_of_user = ptr;
	const char *start_of_host = NULL;
	string_t *quoted = NULL;

	if (quote)
		quoted = t_str_new(256);

	/* it's a URL, see if there is a userpart */
	while(*ptr != '\0' && !i_isspace(*ptr) && *ptr != '/') {
		if (*ptr == '@') {
			start_of_host = ptr;
			break;
		}
		ptr++;
	}

	if (quote) {
		str_truncate(quoted, 0);
		str_append_escaped(quoted, *optr, start_of_user - (*optr));
		o_stream_nsend(output, quoted->data, quoted->used);
	} else {
		o_stream_nsend(output, *optr, start_of_user - (*optr));
	}

	if (start_of_host != NULL && start_of_host != start_of_user) {
		o_stream_nsend_str(output, "#hidden_use-P_to_show#");
	} else if (quote) {
		str_truncate(quoted, 0);
		str_append_escaped(quoted, start_of_user, ptr - start_of_user);
		o_stream_nsend(output, quoted->data, quoted->used);
	} else {
		o_stream_nsend(output, start_of_user, ptr - start_of_user);
	}

	*optr = ptr;
	*_ptr = ptr;
	return TRUE;
}

static inline bool key_ends_with(const char *key, const char *eptr,
				 const char *suffix)
{
	/* take = into account */
	size_t n = strlen(suffix)+1;
	return (eptr-key > (ptrdiff_t)n && str_begins_with(eptr-n, suffix));
}

static bool
hide_secrets_from_value(struct ostream *output, const char *key,
			const char *value)
{
	bool ret = FALSE, quote = value_need_quote(value);
	const char *ptr, *optr, *secret;
	if (*value != '\0' &&
	    (key_ends_with(key, value, "_password") ||
	     key_ends_with(key, value, "_key") ||
	     key_ends_with(key, value, "_nonce") ||
	     str_begins_with(key, "ssl_dh"))) {
		o_stream_nsend_str(output, "# hidden, use -P to show it");
		return TRUE;
	}

	/* Check if we can find anything that has prefix of any of the
	   secrets. It should match things like secret_api_key or pass or password,
	   etc. but not something like nonsecret. */
	optr = ptr = value;
	while((ptr = find_next_secret(ptr, &secret)) != NULL) {
		if (strstr(secret, "://") != NULL) {
			ptr += strlen(secret);
			if ((ret = hide_url_userpart_from_value(output, &ptr, &optr, quote)))
				continue;
		}
		/* we have found something that we hide, and will deal with output
		   here. */
		ret = TRUE;
		if (ptr == value ||
		    (ptr > value && !i_isalnum(ptr[-1]))) {
			size_t len;
			while(*ptr != '\0') {
				if (*ptr == '=' || i_isspace(*ptr))
					break;
				ptr++;
			}
			while(i_isspace(*ptr))
				ptr++;
			len = (size_t)(ptr-optr);
			if (quote) {
				string_t *quoted = t_str_new(len*2);
				str_append_escaped(quoted, optr, len);
				o_stream_nsend(output,
					       quoted->data, quoted->used);
			} else {
				o_stream_nsend(output, optr, len);
			}
			if (*ptr == '=') {
				o_stream_nsend(output, ptr, 1);
				o_stream_nsend_str(output, "#hidden_use-P_to_show#");
				while(*ptr != '\0' && !i_isspace(*ptr) &&
				      *ptr != ';' && *ptr != ':')
					ptr++;
			}
			optr = ptr;
		} else {
			/* "secret" is prefixed with alphanumeric character,
			   e.g. "nopassword". So it's not really a secret.
			   Skip forward to avoid infinite loop. */
			ptr++;
		}
	};
	/* if we are dealing with output, send rest here */
	if (ret) {
		if (quote)
			o_stream_nsend_str(output, str_escape(optr));
		else
			o_stream_nsend_str(output, optr);
	}
	return ret;
}

static void ATTR_NULL(4)
config_dump_human_output(struct config_dump_human_context *ctx,
			 struct ostream *output, unsigned int indent,
			 const char *setting_name_filter,
			 const char *alt_setting_name_filter,
			 bool hide_key, bool default_hide_passwords,
			 const char *strip_prefix)
{
	ARRAY_TYPE(const_string) prefixes_arr;
	ARRAY_TYPE(prefix_stack) prefix_stack;
	struct prefix_stack prefix;
	const char *const *strings, *p, *str, *const *prefixes;
	const char *key, *key2, *value;
	unsigned int i, j, count, prefix_count;
	unsigned int prefix_idx = UINT_MAX;
	size_t len, skip_len, setting_name_filter_len;
	size_t alt_setting_name_filter_len;

	setting_name_filter_len = setting_name_filter == NULL ? 0 :
		strlen(setting_name_filter);
	alt_setting_name_filter_len = alt_setting_name_filter == NULL ? 0 :
		strlen(alt_setting_name_filter);
	if (config_export_all_parsers(&ctx->export_ctx) < 0)
		i_unreached(); /* settings aren't checked - this can't happen */

	array_sort(&ctx->strings, config_string_cmp);
	strings = array_get(&ctx->strings, &count);

	/* strings are sorted so that all lists come first */
	p_array_init(&prefixes_arr, ctx->pool, 32);
	for (i = 0; i < count && strings[i][0] == LIST_KEY_PREFIX[0]; i++) T_BEGIN {
		p = strchr(strings[i], '=');
		i_assert(p != NULL && p[1] == '\0');
		/* "strlist=" */
		str = p_strdup_printf(ctx->pool, "%s/",
				      t_strcut(strings[i]+1, '='));
		array_push_back(&prefixes_arr, &str);
	} T_END;
	prefixes = array_get(&prefixes_arr, &prefix_count);

	p_array_init(&prefix_stack, ctx->pool, 8);
	for (; i < count; i++) T_BEGIN {
		value = strchr(strings[i], '=');
		i_assert(value != NULL);

		key = t_strdup_until(strings[i], value++);

		bool hide_passwords = default_hide_passwords;
		if (setting_name_filter_len > 0) {
			/* See if this setting matches the name filter.
			   If we're asking for a full specific setting,
			   don't hide passwords. */
			if (strncmp(setting_name_filter, key,
				    setting_name_filter_len) == 0 &&
			    (key[setting_name_filter_len] == '/' ||
			     key[setting_name_filter_len] == '\0')) {
				/* match */
				if (key[setting_name_filter_len] == '\0')
					hide_passwords = FALSE;
			} else if (alt_setting_name_filter_len > 0 &&
				   (strncmp(alt_setting_name_filter, key,
					    alt_setting_name_filter_len) == 0 &&
				    (key[alt_setting_name_filter_len] == '/' ||
				     key[alt_setting_name_filter_len] == '\0'))) {
				/* alt match */
				if (key[alt_setting_name_filter_len] == '\0')
					hide_passwords = FALSE;
			} else
				goto end;
		}
	again:
		j = 0;
		/* if there are open sections and this key isn't in it,
		   close the sections */
		while (prefix_idx != UINT_MAX) {
			len = strlen(prefixes[prefix_idx]);
			if (strncmp(prefixes[prefix_idx], key, len) != 0) {
				prefix = prefix_stack_pop(&prefix_stack);
				indent--;
				if (!hide_key) {
					o_stream_nsend(output, indent_str, indent*2);
					o_stream_nsend_str(output, "}\n");
				}
				prefix_idx = prefix.prefix_idx;
			} else {
				/* keep the prefix */
				j = prefix_idx + 1;
				break;
			}
		}
		/* see if this key is in some section */
		for (; j < prefix_count; j++) {
			len = strlen(prefixes[j]);
			if (strncmp(prefixes[j], key, len) == 0) {
				key2 = key + (prefix_idx == UINT_MAX ? 0 :
					      strlen(prefixes[prefix_idx]));
				prefix_idx = j;
				prefix.prefix_idx = prefix_idx;
				array_push_back(&prefix_stack, &prefix);

				str_append_max(ctx->list_prefix, indent_str, indent*2);
				p = strchr(key2, '/');
				if (p != NULL)
					str_append_data(ctx->list_prefix, key2, p - key2);
				else
					str_append(ctx->list_prefix, key2);
				str_append(ctx->list_prefix, " {\n");
				indent++;

				goto again;
			}
		}
		if (!hide_key) {
			o_stream_nsend(output, str_data(ctx->list_prefix),
				       str_len(ctx->list_prefix));
		}
		str_truncate(ctx->list_prefix, 0);
		ctx->list_prefix_sent = TRUE;

		skip_len = prefix_idx == UINT_MAX ? 0 : strlen(prefixes[prefix_idx]);
		i_assert(skip_len == 0 ||
			 strncmp(prefixes[prefix_idx], strings[i], skip_len) == 0);
		if (!hide_key)
			o_stream_nsend(output, indent_str, indent*2);
		key = strings[i] + skip_len;
		const char *full_key = key;
		if (strip_prefix != NULL && str_begins(key, strip_prefix, &key))
			key++;
		value = strchr(key, '=');
		i_assert(value != NULL);
		if (!hide_key) {
			o_stream_nsend(output, key, value-key);
			o_stream_nsend_str(output, " = ");
		} else {
			if (output->offset != 0)
				i_fatal("Multiple settings matched with -h parameter");
		}
		if (hide_passwords &&
		    hide_secrets_from_value(output, full_key, value+1))
			/* sent */
			;
		else if (!value_need_quote(value+1))
			o_stream_nsend_str(output, value+1);
		else {
			o_stream_nsend(output, "\"", 1);
			o_stream_nsend_str(output, str_escape(value+1));
			o_stream_nsend(output, "\"", 1);
		}
		o_stream_nsend(output, "\n", 1);
	end: ;
	} T_END;

	while (prefix_idx != UINT_MAX) {
		prefix = prefix_stack_pop(&prefix_stack);
		prefix_idx = prefix.prefix_idx;
		indent--;
		if (!hide_key) {
			o_stream_nsend(output, indent_str, indent*2);
			o_stream_nsend_str(output, "}\n");
		}
	}
}

static const char *filter_name_escaped(const char *name)
{
	name = settings_section_unescape(name);
	if (name[0] == '\0')
		return "\"\"";
	if (strpbrk(name, " \"{=<'$") == NULL)
		return name;

	string_t *dest = t_str_new(64);
	str_append_c(dest, '"');
	str_append_escaped(dest, name, strlen(name));
	str_append_c(dest, '"');
	return str_c(dest);
}

static void
config_dump_named_filters(string_t *str, unsigned int *indent,
			  const struct config_filter *filter)
{
	if (filter->filter_name == NULL)
		return;

	const char *p = strchr(filter->filter_name, '/');
	str_append_max(str, indent_str, (*indent) * 2);
	if (p == NULL)
		str_printfa(str, "%s {\n", filter->filter_name);
	else {
		/* SET_FILTER_ARRAY */
		str_printfa(str, "%s %s {\n",
			    t_strdup_until(filter->filter_name, p),
			    filter_name_escaped(p+1));
	}
	*indent += 1;
}

static unsigned int
config_dump_filter_begin(string_t *str, unsigned int indent,
			 const struct config_filter *filter)
{
	if (filter->local_bits > 0) {
		str_append_max(str, indent_str, indent*2);
		str_printfa(str, "local %s", net_ip2addr(&filter->local_net));

		if (IPADDR_IS_V4(&filter->local_net)) {
			if (filter->local_bits != 32)
				str_printfa(str, "/%u", filter->local_bits);
		} else {
			if (filter->local_bits != 128)
				str_printfa(str, "/%u", filter->local_bits);
		}
		str_append(str, " {\n");
		indent++;
	}

	if (filter->local_name != NULL) {
		str_append_max(str, indent_str, indent*2);
		str_printfa(str, "local_name %s {\n", filter->local_name);
		indent++;
	}

	if (filter->remote_bits > 0) {
		str_append_max(str, indent_str, indent*2);
		str_printfa(str, "remote %s", net_ip2addr(&filter->remote_net));

		if (IPADDR_IS_V4(&filter->remote_net)) {
			if (filter->remote_bits != 32)
				str_printfa(str, "/%u", filter->remote_bits);
		} else {
			if (filter->remote_bits != 128)
				str_printfa(str, "/%u", filter->remote_bits);
		}
		str_append(str, " {\n");
		indent++;
	}
	if (filter->service != NULL) {
		str_append_max(str, indent_str, indent*2);
		str_printfa(str, "protocol %s {\n", filter->service);
		indent++;
	}
	config_dump_named_filters(str, &indent, filter);
	return indent;
}

static void
config_dump_filter_end(struct ostream *output, unsigned int indent,
		       unsigned int parent_indent)
{
	while (indent > parent_indent) {
		indent--;
		o_stream_nsend(output, indent_str, indent*2);
		o_stream_nsend(output, "}\n", 2);
	}
}

static void
config_dump_human_filter_path(enum config_dump_scope scope,
			      const char *const *set_filter_path,
			      struct config_filter_parser *filter_parser,
			      struct ostream *output, unsigned int indent,
			      string_t *list_prefix, bool *list_prefix_sent,
			      bool hide_key, bool hide_passwords)
{
	for (; filter_parser != NULL; filter_parser = filter_parser->next) {
		const char *suffix, *set_name_filter = NULL;
		const char *const *sub_filter_path = set_filter_path;

		if (set_filter_path[0] == NULL) {
			/* show everything */
		} else if (filter_parser->filter.filter_name == NULL) {
			/* not a named filter / array - can't match */
			continue;
		} else if (!str_begins(filter_parser->filter.filter_name,
				       set_filter_path[0], &suffix)) {
			/* filter name doesn't match the path prefix at all. */
			continue;
		} else if (suffix[0] == '\0') {
			/* filter name match (e.g. "mail_attribute_dict") */
			set_name_filter = set_filter_path[1];
			sub_filter_path++;
		} else if (suffix[0] != '/') {
			/* filter name doesn't match the path */
		} else if (set_filter_path[1] == NULL) {
			/* filter array name prefix match (e.g. "service") */
			sub_filter_path++;
		} else if (strcmp(suffix+1, set_filter_path[1]) == 0) {
			/* filter array match */
			sub_filter_path += 2;

			if (sub_filter_path[0] == NULL) {
				/* Show all settings under this section */
			} else if (sub_filter_path[1] == NULL) {
				/* One more string in the path - it could be
				   either a filter or a setting name.
				   Check both. */
				set_name_filter = sub_filter_path[0];
			} else {
				/* There is at least one more '/' in the path.
				   It could be either another filter, or it
				   could be e.g. "plugin/key". */
				set_name_filter = t_strarray_join(sub_filter_path, "/");
			}
		} else {
			continue;
		}

		struct config_dump_human_context *ctx;
		unsigned int sub_indent;
		size_t parent_list_prefix_len = str_len(list_prefix);
		/* If we're asking for a specific setting, don't hide
		   passwords. */
		bool sub_hide_passwords = set_name_filter != NULL ?
			FALSE : hide_passwords;

		ctx = config_dump_human_init(scope);
		sub_indent = hide_key ? 0 :
			config_dump_filter_begin(list_prefix, indent,
						 &filter_parser->filter);
		config_export_set_module_parsers(ctx->export_ctx,
						 filter_parser->module_parsers);
		str_append_str(ctx->list_prefix, list_prefix);
		const char *filter_key =
			!filter_parser->filter.filter_name_array ? NULL :
			t_strcut(filter_parser->filter.filter_name, '/');

		const char *alt_set_name_filter =
			set_name_filter != NULL && filter_key != NULL ?
			t_strdup_printf("%s_%s", filter_key, set_name_filter) :
			NULL;
		config_dump_human_output(ctx, output, sub_indent,
					 set_name_filter,
					 alt_set_name_filter, hide_key,
					 sub_hide_passwords, filter_key);

		bool sub_list_prefix_sent = ctx->list_prefix_sent;
		if (sub_list_prefix_sent) {
			*list_prefix_sent = TRUE;
			str_truncate(list_prefix, 0);
		}
		config_dump_human_deinit(ctx);

		config_dump_human_filter_path(scope, sub_filter_path,
			filter_parser->children_head, output, sub_indent,
			list_prefix, &sub_list_prefix_sent,
			hide_key, hide_passwords);
		if (sub_list_prefix_sent) {
			*list_prefix_sent = TRUE;
			config_dump_filter_end(output, sub_indent, indent);
		}
		str_truncate(list_prefix, parent_list_prefix_len);
	}
}

static int
config_dump_human(enum config_dump_scope scope,
		  const char *setting_name_filter,
		  bool hide_key, bool hide_passwords)
{
	struct config_filter_parser *filter_parser;
	struct config_dump_human_context *ctx;
	struct ostream *output;
	const char *str;
	int ret = 0;

	output = o_stream_create_fd(STDOUT_FILENO, 0);
	o_stream_set_no_error_handling(output, TRUE);
	o_stream_cork(output);

	filter_parser = config_parsed_get_global_filter_parser(config);

	/* Check for the setting always even with a filter - it might be
	   e.g. plugin/key strlist */
	ctx = config_dump_human_init(scope);
	config_export_set_module_parsers(ctx->export_ctx,
					 filter_parser->module_parsers);
	config_dump_human_output(ctx, output, 0, setting_name_filter, NULL,
				 hide_key, hide_passwords, NULL);
	config_dump_human_deinit(ctx);

	string_t *list_prefix = t_str_new(128);
	bool list_prefix_sent = FALSE;
	const char *const *set_filter_path =
		setting_name_filter == NULL ? empty_str_array :
		t_strsplit(setting_name_filter, "/");
	if (scope == CONFIG_DUMP_SCOPE_CHANGED)
		scope = CONFIG_DUMP_SCOPE_SET;
	else
		scope = CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES;
	config_dump_human_filter_path(scope, set_filter_path,
				      filter_parser->children_head, output, 0,
				      list_prefix, &list_prefix_sent,
				      hide_key, hide_passwords);

	/* flush output before writing errors */
	o_stream_uncork(output);
	array_foreach_elem(config_parsed_get_errors(config), str) {
		i_error("%s", str);
		ret = -1;
	}
	o_stream_destroy(&output);
	return ret;
}

struct hostname_format {
	const char *prefix, *suffix;
	unsigned int numcount;
	bool zeropadding;
};

static void
hostname_format_write(string_t *str, const struct hostname_format *fmt,
		      unsigned int num)
{
	str_truncate(str, 0);
	str_append(str, fmt->prefix);
	if (!fmt->zeropadding)
		str_printfa(str, "%d", num);
	else
		str_printfa(str, "%0*d", fmt->numcount, num);
	str_append(str, fmt->suffix);
}

static void hostname_verify_format(const char *arg)
{
	struct hostname_format fmt;
	const char *p;
	unsigned char hash[GUID_128_HOST_HASH_SIZE];
	unsigned int n, limit;
	HASH_TABLE(void *, void *) hosts;
	void *key, *value;
	string_t *host;
	const char *host2;
	bool duplicates = FALSE;

	i_zero(&fmt);
	if (arg != NULL) {
		/* host%d, host%2d, host%02d */
		p = strchr(arg, '%');
		if (p == NULL)
			i_fatal("Host parameter missing %%d");
		fmt.prefix = t_strdup_until(arg, p++);
		if (*p == '0') {
			fmt.zeropadding = TRUE;
			p++;
		}
		if (!i_isdigit(*p))
			fmt.numcount = 1;
		else
			fmt.numcount = *p++ - '0';
		if (*p++ != 'd')
			i_fatal("Host parameter missing %%d");
		fmt.suffix = p;
	} else {
		/* detect host1[suffix] vs host01[suffix] */
		size_t len = strlen(my_hostname);
		while (len > 0 && !i_isdigit(my_hostname[len-1]))
			len--;
		fmt.suffix = my_hostname + len;
		fmt.numcount = 0;
		while (len > 0 && i_isdigit(my_hostname[len-1])) {
			len--;
			fmt.numcount++;
		}
		if (my_hostname[len] == '0')
			fmt.zeropadding = TRUE;
		fmt.prefix = t_strndup(my_hostname, len);
		if (fmt.numcount == 0) {
			i_fatal("Hostname '%s' has no digits, can't verify",
				my_hostname);
		}
	}
	for (n = 0, limit = 1; n < fmt.numcount; n++)
		limit *= 10;
	host = t_str_new(128);
	hash_table_create_direct(&hosts, default_pool, limit);
	for (n = 0; n < limit; n++) {
		hostname_format_write(host, &fmt, n);

		guid_128_host_hash_get(str_c(host), hash);
		i_assert(sizeof(key) >= sizeof(hash));
		key = NULL; memcpy(&key, hash, sizeof(hash));

		value = hash_table_lookup(hosts, key);
		if (value != NULL) {
			host2 = t_strdup(str_c(host));
			hostname_format_write(host, &fmt,
				POINTER_CAST_TO(value, unsigned int)-1);
			i_error("Duplicate host hashes: %s and %s",
				str_c(host), host2);
			duplicates = TRUE;
		} else {
			hash_table_insert(hosts, key, POINTER_CAST(n+1));
		}
	}
	hash_table_destroy(&hosts);

	if (duplicates)
		lib_exit(EX_CONFIG);
	else {
		host2 = t_strdup(str_c(host));
		hostname_format_write(host, &fmt, 0);
		printf("No duplicate host hashes in %s .. %s\n",
		       str_c(host), host2);
		lib_exit(0);
	}
}

static void check_wrong_config(const char *config_path)
{
	const char *base_dir, *symlink_path, *prev_path, *error;

	base_dir = config_module_parsers_get_setting(
			config_parsed_get_module_parsers(config),
			"master_service", "base_dir");
	symlink_path = t_strconcat(base_dir, "/"PACKAGE".conf", NULL);
	if (t_readlink(symlink_path, &prev_path, &error) < 0) {
		if (errno != ENOENT)
			i_error("t_readlink(%s) failed: %s", symlink_path, error);
		return;
	}

	if (strcmp(prev_path, config_path) != 0) {
		i_warning("Dovecot was last started using %s, "
			  "but this config is %s", prev_path, config_path);
	}
}

static void failure_exit_callback(int *status)
{
	/* don't use EX_CONFIG, because it often causes MTAs to bounce
	   the mails back. */
	*status = EX_TEMPFAIL;
}

int main(int argc, char *argv[])
{
	enum master_service_flags master_service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME;
	enum config_dump_scope scope = CONFIG_DUMP_SCOPE_DEFAULT;
	const char *orig_config_path, *config_path;
	const char *import_environment, *error;
	char **exec_args = NULL, **setting_name_filters = NULL;
	unsigned int i;
	int c, ret, ret2;
	bool config_path_specified, expand_vars = FALSE, hide_key = FALSE;
	bool simple_output = FALSE, check_full_config = FALSE;
	bool hide_obsolete_warnings = FALSE;
	bool dump_defaults = FALSE, host_verify = FALSE, dump_full = FALSE;
	bool print_plugin_banner = FALSE, hide_passwords = TRUE;

	if (getenv("USE_SYSEXITS") != NULL) {
		/* we're coming from (e.g.) LDA */
		i_set_failure_exit_callback(failure_exit_callback);
	}

	master_service = master_service_init("config", master_service_flags,
					     &argc, &argv, "aCdFhHm:nNpPwxs");
	orig_config_path = t_strdup(master_service_get_config_path(master_service));

	i_set_failure_prefix("doveconf: ");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			scope = CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN;
			break;
		case 'C':
			check_full_config = TRUE;
			break;
		case 'd':
			scope = CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN;
			dump_defaults = TRUE;
			break;
		case 'F':
			dump_full = TRUE;
			simple_output = TRUE;
			expand_vars = TRUE;
			break;
		case 'h':
			hide_key = TRUE;
			break;
		case 'H':
			host_verify = TRUE;
			break;
		case 'm':
		case 'p':
			/* not supported anymore - ignore */
			break;
		case 'n':
			scope = CONFIG_DUMP_SCOPE_CHANGED;
			break;
		case 'N':
			scope = CONFIG_DUMP_SCOPE_SET;
			break;
		case 'P':
			hide_passwords = FALSE;
			break;
		case 's':
			scope = CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN;
			break;
		case 'w':
			hide_obsolete_warnings = TRUE;
			break;
		case 'x':
			expand_vars = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	config_path = master_service_get_config_path(master_service);
	/* use strcmp() instead of !=, because dovecot -n always gives us
	   -c parameter */
	config_path_specified = strcmp(config_path, orig_config_path) != 0;

	if (host_verify)
		hostname_verify_format(argv[optind]);

	if (scope == CONFIG_DUMP_SCOPE_DEFAULT) {
		if (argv[optind] == NULL) {
			/* "doveconf" without parameters */
			scope = CONFIG_DUMP_SCOPE_CHANGED;
		} else {
			/* "doveconf setting_name" should output it even if
			   it is the default. */
			scope = CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN;
		}
	}
	if (dump_full && argv[optind] != NULL) {
		if (argv[optind] == NULL)
			i_fatal("Missing command for -F");
		exec_args = &argv[optind];
	} else if (argv[optind] != NULL) {
		/* print only a single config setting */
		setting_name_filters = argv+optind;
		if (scope == CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN)
			scope = CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN;
	} else if (!simple_output) {
		/* print the config file path before parsing it, so in case
		   of errors it's still shown */
		printf("# "DOVECOT_VERSION_FULL": %s\n", config_path);
		print_plugin_banner = TRUE;
		fflush(stdout);
	}
	master_service_init_finish(master_service);
	set_config_binary(TRUE);
	config_parse_load_modules();

	if (print_plugin_banner) {
		struct module *m;

		for (m = modules; m != NULL; m = m->next) {
			const char **str = module_get_symbol_quiet(m,
				t_strdup_printf("%s_doveconf_banner", m->name));
			if (str != NULL)
				printf("# %s\n", *str);
		}
	}

	enum config_parse_flags flags = CONFIG_PARSE_FLAG_RETURN_BROKEN_CONFIG;
	if (expand_vars)
		flags |= CONFIG_PARSE_FLAG_EXPAND_VALUES;
	if (dump_full && exec_args != NULL && !check_full_config)
		flags |= CONFIG_PARSE_FLAG_DELAY_ERRORS;
	if (hide_obsolete_warnings)
		flags |= CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS;
	if ((ret = config_parse_file(dump_defaults ? NULL : config_path,
				     flags, &config, &error)) == 0 &&
	    access(EXAMPLE_CONFIG_DIR, X_OK) == 0) {
		i_fatal("%s (copy example configs from "EXAMPLE_CONFIG_DIR"/)",
			error);
	}

	if ((ret == -1 && exec_args != NULL) || ret == 0 || ret == -2)
		i_fatal("%s", error);

	if (dump_full && exec_args == NULL) {
		ret2 = config_dump_full(config,
					CONFIG_DUMP_FULL_DEST_STDOUT,
					0, &import_environment);
	} else if (dump_full) {
		int temp_fd = config_dump_full(config,
					       CONFIG_DUMP_FULL_DEST_TEMPDIR,
					       0, &import_environment);
		if (getenv(DOVECOT_PRESERVE_ENVS_ENV) != NULL) {
			/* Standalone binary is getting its configuration via
			   doveconf. Clean the environment before calling it.
			   Do this only if the environment exists, because
			   lib-master doesn't set it if it doesn't want the
			   environment to be cleaned (e.g. -k parameter). */
			master_service_import_environment(import_environment);
			master_service_env_clean();
		}
		if (temp_fd != -1) {
			env_put(DOVECOT_CONFIG_FD_ENV, dec2str(temp_fd));
			execvp(exec_args[0], exec_args);
			i_fatal("execvp(%s) failed: %m", exec_args[0]);
		}
		ret2 = -1;
	} else if (setting_name_filters != NULL) {
		ret2 = 0;
		/* ignore settings-check failures in configuration. this allows
		   using doveconf to lookup settings for things like install or
		   uninstall scripts where the configuration might
		   (temporarily) not be fully usable */
		ret = 0;
		for (i = 0; setting_name_filters[i] != NULL; i++) {
			(void)config_dump_human(scope, setting_name_filters[i],
						hide_key, hide_passwords);
		}
	} else {
		const char *info, *mail_location, *version;

		mail_location = config_module_parsers_get_setting(
			config_parsed_get_module_parsers(config),
			"mail_storage", "mail_location");
		info = sysinfo_get(mail_location);
		if (*info != '\0')
			printf("# %s\n", info);
		printf("# Hostname: %s\n", my_hostdomain());
		if (config_parsed_get_version(config, &version))
			printf("dovecot_config_version = %s\n", version);
		if (!config_path_specified)
			check_wrong_config(config_path);
		if (scope == CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN)
			printf("# NOTE: Send doveconf -n output instead when asking for help.\n");
		fflush(stdout);
		ret2 = config_dump_human(scope, NULL, hide_key, hide_passwords);
	}

	if (ret < 0) {
		/* delayed error */
		i_fatal("%s", error);
	}
	if (ret2 < 0)
		i_fatal("Errors in configuration");

	config_parsed_free(&config);
	old_settings_deinit_global();
	module_dir_unload(&modules);
	config_parser_deinit();
	master_service_deinit(&master_service);
        return 0;
}
