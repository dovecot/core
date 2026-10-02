/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "ostream.h"
#include "settings.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "config-filter.h"
#include "config-parser.h"
#include "config-request.h"
#include "config-dump-full.h"
#include "all-settings.h"
#include "test-common.h"
#include "test-dir.h"

#define TEST_CONFIG_FILE "config"

static const struct config_service test_config_all_services[] = { { NULL, NULL } };
const struct config_service *config_all_services = test_config_all_services;

struct test_settings {
	pool_t pool;
	const char *protocols;
	const char *key;
	const char *key_protocol;
	const char *key_net;
	const char *key_local_name;
	const char *key_service;
	const char *key_group;
	const char *key_named;
	ARRAY_TYPE(const_string) namespaces;
	ARRAY_TYPE(const_string) services;
};

struct test_namespace_settings {
	pool_t pool;
	const char *namespace_name;
	ARRAY_TYPE(const_string) mailboxes;
};

struct test_mailbox_settings {
	pool_t pool;
	const char *mailbox_name;
};

static const struct setting_define test_settings_defs[] = {
	SETTING_DEFINE_STRUCT_STR("protocols", protocols, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key", key, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_protocol", key_protocol, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_net", key_net, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_local_name", key_local_name, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_service", key_service, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_group", key_group, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key_named", key_named, struct test_settings),
	{ .type = SET_FILTER_ARRAY, .key = "namespace",
	  .offset = offsetof(struct test_settings, namespaces),
	  .filter_array_field_name = "namespace_name" },
	{ .type = SET_FILTER_ARRAY, .key = "service",
	  .offset = offsetof(struct test_settings, services),
	  .filter_array_field_name = "service_name" },
	{ .type = SET_FILTER_NAME, .key = "named" },
	SETTING_DEFINE_LIST_END
};

static const struct test_settings test_settings_defaults = {
	.protocols = "imap pop3",
	.key = "default",
	.key_protocol = "default",
	.key_net = "default",
	.key_local_name = "default",
	.key_service = "default",
	.key_group = "default",
	.key_named = "default",
	.namespaces = ARRAY_INIT,
	.services = ARRAY_INIT,
};

static const struct setting_parser_info test_settings_info = {
	.name = "test",
	.defines = test_settings_defs,
	.defaults = &test_settings_defaults,

	.struct_size = sizeof(struct test_settings),
	.pool_offset1 = 1 + offsetof(struct test_settings, pool),
};

static const struct setting_define test_namespace_settings_defs[] = {
	SETTING_DEFINE_STRUCT_STR("namespace_name", namespace_name,
				  struct test_namespace_settings),
	{ .type = SET_FILTER_ARRAY, .key = "mailbox",
	  .offset = offsetof(struct test_namespace_settings, mailboxes),
	  .filter_array_field_name = "mailbox_name" },
	SETTING_DEFINE_LIST_END
};

static const struct test_namespace_settings test_namespace_settings_defaults = {
	.namespace_name = "",
	.mailboxes = ARRAY_INIT,
};

static const struct setting_parser_info test_namespace_settings_info = {
	.name = "test_namespace",
	.defines = test_namespace_settings_defs,
	.defaults = &test_namespace_settings_defaults,

	.struct_size = sizeof(struct test_namespace_settings),
	.pool_offset1 = 1 + offsetof(struct test_namespace_settings, pool),
};

static const struct setting_define test_mailbox_settings_defs[] = {
	SETTING_DEFINE_STRUCT_STR("mailbox_name", mailbox_name,
				  struct test_mailbox_settings),
	SETTING_DEFINE_LIST_END
};

static const struct test_mailbox_settings test_mailbox_settings_defaults = {
	.mailbox_name = "",
};

static const struct setting_parser_info test_mailbox_settings_info = {
	.name = "test_mailbox",
	.defines = test_mailbox_settings_defs,
	.defaults = &test_mailbox_settings_defaults,

	.struct_size = sizeof(struct test_mailbox_settings),
	.pool_offset1 = 1 + offsetof(struct test_mailbox_settings, pool),
};

struct test_service_settings {
	pool_t pool;
	const char *service_name;
};

static const struct setting_define test_service_settings_defs[] = {
	SETTING_DEFINE_STRUCT_STR("service_name", service_name,
				  struct test_service_settings),
	SETTING_DEFINE_LIST_END
};

static const struct test_service_settings test_service_settings_defaults = {
	.service_name = "",
};

static const struct setting_parser_info test_service_settings_info = {
	.name = "test_service",
	.defines = test_service_settings_defs,
	.defaults = &test_service_settings_defaults,

	.struct_size = sizeof(struct test_service_settings),
	.pool_offset1 = 1 + offsetof(struct test_service_settings, pool),
};

static const struct setting_parser_info *const infos[] = {
	&test_settings_info,
	&test_namespace_settings_info,
	&test_mailbox_settings_info,
	&test_service_settings_info,
	NULL
};

const struct setting_parser_info *const *all_infos = infos;

static const char *test_config =
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key = global\n"
"namespace inbox {\n"
"  key = inbox\n"
"  mailbox foo {\n"
"    key = inbox-foo\n"
"  }\n"
"  mailbox \"with space/and slash\" {\n"
"    key = inbox-escaped\n"
"  }\n"
"}\n"
"namespace other {\n"
"  key = other\n"
"}\n"
"mailbox foo {\n"
"  key = any-foo\n"
"}\n"
"mailbox bar {\n"
"  key = any-bar\n"
"}\n"
"protocol imap {\n"
"  key_protocol = imap\n"
"}\n"
"protocol !imap {\n"
"  key_protocol = not-imap\n"
"}\n"
"protocol pop3 {\n"
"  namespace inbox {\n"
"    key = pop3-inbox\n"
"  }\n"
"}\n"
"local 10.0.0.0/8 {\n"
"  key_net = local-10\n"
"  local 10.1.0.0/16 {\n"
"    key_net = local-10.1\n"
"  }\n"
"}\n"
"remote 192.168.0.0/16 {\n"
"  key_net = remote-192.168\n"
"}\n"
"remote fe80::/16 {\n"
"  key_net = remote-fe80\n"
"}\n"
"local_name *.example.com {\n"
"  key_local_name = wildcard\n"
"}\n"
"local_name imap.example.com {\n"
"  key_local_name = exact\n"
"}\n"
"service imap {\n"
"  key_service = imap\n"
"}\n"
"named {\n"
"  key_named = named\n"
"}\n"
"group @grp g1 {\n"
"  key_group = g1\n"
"  namespace inbox {\n"
"    key_group = g1-inbox\n"
"  }\n"
"}\n"
"group @grp g2 {\n"
"  key_group = g2\n"
"}\n"
"namespace other {\n"
"  @grp = g1\n"
"}\n"
"namespace inbox {\n"
"  @grp = g1\n"
"}\n"
"mailbox bar {\n"
"  @grp = g2\n"
"}\n";

static void write_config_file(const char *contents)
{
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	struct ostream *os = o_stream_create_file(config_file, 0, 0600, 0);
	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static int test_config_dump(void)
{
	struct config_parsed *config;
	const char *error = NULL;

	write_config_file(test_config);
	if (config_parse_file(test_dir_prepend(TEST_CONFIG_FILE),
			      CONFIG_PARSE_FLAG_NO_DEFAULTS,
			      NULL, &config, &error) != 1)
		i_fatal("config_parse_file(): %s", error);

	int fd = config_dump_full(config, CONFIG_DUMP_FULL_DEST_TEMPDIR,
				  0, NULL);
	test_assert(fd != -1);
	config_parsed_free(&config);
	return fd;
}

static struct settings_root *
test_settings_read(const char *service_name, const char *protocol_name)
{
	const char *const *specific_protocols;
	const char *error;

	int fd = test_config_dump();
	struct settings_root *root = settings_root_init();
	if (settings_read(root, fd, "(test)", service_name, protocol_name, 0,
			  &specific_protocols, &error) < 0)
		i_fatal("settings_read(): %s", error);
	i_close_fd(&fd);
	return root;
}

static const struct test_settings *
test_settings_get(struct event *event, const char *filter_key,
		  const char *filter_value)
{
	const struct test_settings *set;
	const char *error;
	int ret;

	if (filter_key == NULL) {
		ret = settings_get(event, &test_settings_info, 0,
				   &set, &error) < 0 ? -1 : 1;
	} else if (filter_value == NULL) {
		struct event *child = event_create(event);
		settings_event_add_filter_name(child, filter_key);
		ret = settings_get(child, &test_settings_info, 0,
				   &set, &error) < 0 ? -1 : 1;
		event_unref(&child);
	} else {
		ret = settings_try_get_filter(event, filter_key, filter_value,
					      &test_settings_info, 0,
					      &set, &error);
	}
	if (ret < 0)
		i_fatal("settings_get() failed: %s", error);
	return ret == 0 ? NULL : set;
}

static const char *
test_get_key(struct event *event, const char *filter_key,
	     const char *filter_value, size_t field_offset)
{
	const struct test_settings *set =
		test_settings_get(event, filter_key, filter_value);
	if (set == NULL)
		return "<none>";
	const char *value =
		t_strdup(*(const char *const *)CONST_PTR_OFFSET(set, field_offset));
	settings_free(set);
	return value;
}

#define test_key(event, filter_key, filter_value, field, expected) \
	test_assert_strcmp(test_get_key(event, filter_key, filter_value, \
		offsetof(struct test_settings, field)), expected)

static struct event *test_event_create(struct settings_root *root)
{
	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, root);
	return event;
}

static void test_config_dump_full_named_filters(void)
{
	test_begin("config dump full - named filters");
	struct settings_root *root = test_settings_read(NULL, "imap");
	struct event *event = test_event_create(root);

	test_key(event, NULL, NULL, key, "global");
	test_key(event, "namespace", "inbox", key, "inbox");
	test_key(event, "namespace", "other", key, "other");
	test_key(event, "namespace", "nonexistent", key, "<none>");
	test_key(event, "mailbox", "foo", key, "any-foo");
	test_key(event, "mailbox", "bar", key, "any-bar");
	test_key(event, "mailbox", "baz", key, "<none>");
	test_key(event, "named", NULL, key_named, "named");
	test_key(event, NULL, NULL, key_named, "default");

	/* mailbox lookups inside namespaces */
	struct event *ns_inbox = event_create(event);
	settings_event_add_list_filter_name(ns_inbox, "namespace", "inbox");
	struct event *ns_other = event_create(event);
	settings_event_add_list_filter_name(ns_other, "namespace", "other");

	test_key(ns_inbox, NULL, NULL, key, "inbox");
	test_key(ns_inbox, "mailbox", "foo", key, "inbox-foo");
	test_key(ns_other, "mailbox", "foo", key, "any-foo");
	test_key(ns_inbox, "mailbox", "bar", key, "any-bar");
	test_key(ns_other, "mailbox", "bar", key, "any-bar");
	test_key(ns_inbox, "mailbox", "with space/and slash", key,
		 "inbox-escaped");
	test_key(ns_other, "mailbox", "with space/and slash", key, "<none>");
	test_key(ns_inbox, "mailbox", "baz", key, "<none>");

	event_unref(&ns_inbox);
	event_unref(&ns_other);
	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_protocol(void)
{
	struct settings_root *root;
	struct event *event;

	test_begin("config dump full - protocol filters");
	/* protocol from settings_read() */
	root = test_settings_read(NULL, "imap");
	event = test_event_create(root);
	test_key(event, NULL, NULL, key_protocol, "imap");
	test_key(event, "namespace", "inbox", key, "inbox");
	event_unref(&event);
	settings_root_deinit(&root);

	root = test_settings_read(NULL, "pop3");
	event = test_event_create(root);
	test_key(event, NULL, NULL, key_protocol, "not-imap");
	test_key(event, "namespace", "inbox", key, "pop3-inbox");
	test_key(event, "namespace", "other", key, "other");
	event_unref(&event);
	settings_root_deinit(&root);

	/* no protocol in settings_read() - use the event's protocol */
	root = test_settings_read(NULL, NULL);
	event = test_event_create(root);
	test_key(event, NULL, NULL, key_protocol, "not-imap");
	test_key(event, "namespace", "inbox", key, "inbox");
	event_add_str(event, "protocol", "imap");
	test_key(event, NULL, NULL, key_protocol, "imap");
	test_key(event, "namespace", "inbox", key, "inbox");
	event_add_str(event, "protocol", "pop3");
	test_key(event, NULL, NULL, key_protocol, "not-imap");
	test_key(event, "namespace", "inbox", key, "pop3-inbox");
	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_nets(void)
{
	struct ip_addr ip;

	test_begin("config dump full - local/remote filters");
	struct settings_root *root = test_settings_read(NULL, "imap");
	struct event *event = test_event_create(root);
	test_key(event, NULL, NULL, key_net, "default");

	struct event *child = event_create(event);
	test_assert(net_addr2ip("10.2.3.4", &ip) == 0);
	event_add_ip(child, "local_ip", &ip);
	test_key(child, NULL, NULL, key_net, "local-10");
	test_assert(net_addr2ip("10.1.3.4", &ip) == 0);
	event_add_ip(child, "local_ip", &ip);
	test_key(child, NULL, NULL, key_net, "local-10.1");
	test_assert(net_addr2ip("11.1.3.4", &ip) == 0);
	event_add_ip(child, "local_ip", &ip);
	test_key(child, NULL, NULL, key_net, "default");
	/* local_ip as string doesn't match */
	event_add_str(child, "local_ip", "10.1.3.4");
	test_key(child, NULL, NULL, key_net, "default");
	event_unref(&child);

	child = event_create(event);
	test_assert(net_addr2ip("192.168.5.5", &ip) == 0);
	event_add_ip(child, "remote_ip", &ip);
	test_key(child, NULL, NULL, key_net, "remote-192.168");
	test_assert(net_addr2ip("::ffff:192.168.5.5", &ip) == 0);
	event_add_ip(child, "remote_ip", &ip);
	test_key(child, NULL, NULL, key_net, "remote-192.168");
	test_assert(net_addr2ip("fe80::1", &ip) == 0);
	event_add_ip(child, "remote_ip", &ip);
	test_key(child, NULL, NULL, key_net, "remote-fe80");
	test_assert(net_addr2ip("fe81::1", &ip) == 0);
	event_add_ip(child, "remote_ip", &ip);
	test_key(child, NULL, NULL, key_net, "default");

	/* local filter is defined before the remote filter, so the remote
	   filter wins */
	test_assert(net_addr2ip("10.1.3.4", &ip) == 0);
	event_add_ip(child, "local_ip", &ip);
	test_key(child, NULL, NULL, key_net, "local-10.1");
	test_assert(net_addr2ip("192.168.5.5", &ip) == 0);
	event_add_ip(child, "remote_ip", &ip);
	test_key(child, NULL, NULL, key_net, "remote-192.168");
	event_unref(&child);

	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_local_name(void)
{
	test_begin("config dump full - local_name filters");
	struct settings_root *root = test_settings_read(NULL, "imap");
	struct event *event = test_event_create(root);
	test_key(event, NULL, NULL, key_local_name, "default");

	struct event *child = event_create(event);
	event_add_str(child, "local_name", "imap.example.com");
	test_key(child, NULL, NULL, key_local_name, "exact");
	event_add_str(child, "local_name", "pop3.example.com");
	test_key(child, NULL, NULL, key_local_name, "wildcard");
	event_add_str(child, "local_name", "example.com");
	test_key(child, NULL, NULL, key_local_name, "default");
	event_add_str(child, "local_name", "imap.example.org");
	test_key(child, NULL, NULL, key_local_name, "default");
	event_unref(&child);

	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_service(void)
{
	struct settings_root *root;
	struct event *event;

	test_begin("config dump full - service filters");
	root = test_settings_read(NULL, NULL);
	event = test_event_create(root);
	test_key(event, NULL, NULL, key_service, "default");
	test_key(event, "service", "imap", key_service, "imap");
	test_key(event, "service", "pop3", key_service, "<none>");
	event_unref(&event);
	settings_root_deinit(&root);

	root = test_settings_read("imap", NULL);
	event = test_event_create(root);
	test_key(event, "service", "imap", key_service, "imap");
	event_unref(&event);
	settings_root_deinit(&root);

	root = test_settings_read("pop3", NULL);
	event = test_event_create(root);
	test_key(event, "service", "imap", key_service, "<none>");
	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_groups(void)
{
	test_begin("config dump full - groups");
	struct settings_root *root = test_settings_read(NULL, "imap");
	struct event *event = test_event_create(root);

	test_key(event, NULL, NULL, key_group, "default");
	test_key(event, "namespace", "other", key_group, "g1");
	/* group's namespace inbox filter */
	test_key(event, "namespace", "inbox", key_group, "g1-inbox");
	test_key(event, "mailbox", "bar", key_group, "g2");
	test_key(event, "mailbox", "bar", key, "any-bar");
	test_key(event, "mailbox", "foo", key_group, "default");

	struct event *ns_other = event_create(event);
	settings_event_add_list_filter_name(ns_other, "namespace", "other");
	/* namespace other includes g1 and mailbox bar includes g2.
	   The innermost filter's include is applied first. */
	test_key(ns_other, "mailbox", "bar", key_group, "g2");
	test_key(ns_other, "mailbox", "foo", key_group, "g1");
	event_unref(&ns_other);

	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

static void test_config_dump_full_overrides(void)
{
	test_begin("config dump full - overrides");
	struct settings_root *root = test_settings_read(NULL, "imap");
	settings_root_override(root, "namespace/inbox/mailbox/foo/key",
			       "override-inbox-foo",
			       SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	settings_root_override(root, "mailbox/bar/key", "override-bar",
			       SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	struct event *event = test_event_create(root);

	struct event *ns_inbox = event_create(event);
	settings_event_add_list_filter_name(ns_inbox, "namespace", "inbox");
	struct event *ns_other = event_create(event);
	settings_event_add_list_filter_name(ns_other, "namespace", "other");

	test_key(ns_inbox, "mailbox", "foo", key, "override-inbox-foo");
	test_key(ns_other, "mailbox", "foo", key, "any-foo");
	test_key(ns_inbox, "mailbox", "bar", key, "override-bar");
	test_key(ns_inbox, NULL, NULL, key, "inbox");
	test_key(event, NULL, NULL, key, "global");

	event_unref(&ns_inbox);
	event_unref(&ns_other);
	event_unref(&event);
	settings_root_deinit(&root);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_config_dump_full_named_filters,
		test_config_dump_full_protocol,
		test_config_dump_full_nets,
		test_config_dump_full_local_name,
		test_config_dump_full_service,
		test_config_dump_full_groups,
		test_config_dump_full_overrides,
		NULL
	};

	test_dir_init("config-dump-full");
	return test_run(test_functions);
}
