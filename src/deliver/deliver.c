/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

/* This is getting pretty horrible. Especially the config file parsing.
   Dovecot v2.0 should have a config file handling process which should help
   with this.. */

#include "lib.h"
#include "lib-signals.h"
#include "file-lock.h"
#include "array.h"
#include "ioloop.h"
#include "hostpid.h"
#include "home-expand.h"
#include "env-util.h"
#include "fd-set-nonblock.h"
#include "istream.h"
#include "istream-seekable.h"
#include "module-dir.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "var-expand.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "mail-namespace.h"
#include "raw-storage.h"
#include "dict-client.h"
#include "auth-client.h"
#include "mail-send.h"
#include "duplicate.h"
#include "mbox-from.h"
#include "../master/syslog-util.h"
#include "../master/syslog-util.c" /* ugly, ugly.. */
#include "deliver.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>

#define DEFAULT_CONFIG_FILE SYSCONFDIR"/dovecot.conf"
#define DEFAULT_SENDMAIL_PATH "/usr/lib/sendmail"
#define DEFAULT_ENVELOPE_SENDER "MAILER-DAEMON"

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
#define MAIL_MAX_MEMORY_BUFFER (1024*128)

static const char *wanted_headers[] = {
	"From", "Message-ID", "Subject", "Return-Path",
	NULL
};

struct deliver_settings *deliver_set;
deliver_mail_func_t *deliver_mail = NULL;

/* FIXME: these two should be in some context struct instead of as globals.. */
static const char *default_mailbox_name = NULL;
static bool saved_mail = FALSE;
static bool tried_default_save = FALSE;
static bool no_mailbox_autocreate = FALSE;
static char *explicit_envelope_sender = NULL;

static struct module *modules;
static struct ioloop *ioloop;

static pool_t plugin_pool;
static ARRAY_DEFINE(plugin_envs, const char *);

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static const char *deliver_get_address(struct mail *mail, const char *header)
{
	struct message_address *addr;
	const char *str;

	if (explicit_envelope_sender != NULL)
		return explicit_envelope_sender;

	if (mail_get_first_header(mail, header, &str) <= 0)
		return NULL;
	addr = message_address_parse(pool_datastack_create(),
				     (const unsigned char *)str,
				     strlen(str), 1, FALSE);
	return addr == NULL || addr->mailbox == NULL || addr->domain == NULL ||
		*addr->mailbox == '\0' || *addr->domain == '\0' ?
		NULL : t_strconcat(addr->mailbox, "@", addr->domain, NULL);
}

static const struct var_expand_table *
get_log_var_expand_table(struct mail *mail, const char *message)
{
	static struct var_expand_table static_tab[] = {
		{ '$', NULL },
		{ 'm', NULL },
		{ 's', NULL },
		{ 'f', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;
	unsigned int i;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = message;
	(void)mail_get_first_header(mail, "Message-ID", &tab[1].value);
	(void)mail_get_first_header(mail, "Subject", &tab[2].value);
	tab[3].value = deliver_get_address(mail, "From");
	for (i = 1; tab[i].key != '\0'; i++)
		tab[i].value = str_sanitize(tab[i].value, 80);
	return tab;
}

static void
deliver_log(struct mail *mail, const char *fmt, ...) ATTR_FORMAT(2, 3);

static void deliver_log(struct mail *mail, const char *fmt, ...)
{
	va_list args;
	string_t *str;
	const char *msg;

	va_start(args, fmt);
	msg = t_strdup_vprintf(fmt, args);

	str = t_str_new(256);
	var_expand(str, deliver_set->log_format,
		   get_log_var_expand_table(mail, msg));
	i_info("%s", str_c(str));
	va_end(args);
}

static struct mailbox *
mailbox_open_or_create_synced(struct mail_namespace *namespaces,
			      struct mail_storage **storage_r, const char *name)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error error;

	ns = mail_namespace_find(namespaces, &name);
	if (ns == NULL) {
		*storage_r = NULL;
		return NULL;
	}
	*storage_r = ns->storage;

	box = mailbox_open(ns->storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	if (box != NULL || no_mailbox_autocreate)
		return box;

	(void)mail_storage_get_last_error(ns->storage, &error);
	if (error != MAIL_ERROR_NOTFOUND)
		return NULL;

	/* try creating it. */
	if (mail_storage_mailbox_create(ns->storage, name, FALSE) < 0)
		return NULL;

	/* and try opening again */
	box = mailbox_open(ns->storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	if (box == NULL)
		return NULL;

	if (mailbox_sync(box, 0, 0, NULL) < 0) {
		mailbox_close(&box);
		return NULL;
	}
	return box;
}

int deliver_save(struct mail_namespace *namespaces,
		 struct mail_storage **storage_r, const char *mailbox,
		 struct mail *mail, enum mail_flags flags,
		 const char *const *keywords)
{
	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_keywords *kw;
	enum mail_error error;
	const char *mailbox_name;
	int ret = 0;

	if (strcmp(mailbox, default_mailbox_name) == 0)
		tried_default_save = TRUE;

	mailbox_name = str_sanitize(mailbox, 80);
	box = mailbox_open_or_create_synced(namespaces, storage_r, mailbox);
	if (box == NULL) {
		if (*storage_r == NULL) {
			deliver_log(mail,
				    "save failed to %s: Unknown namespace",
				    mailbox_name);
			return -1;
		}
		deliver_log(mail, "save failed to %s: %s", mailbox_name,
			    mail_storage_get_last_error(*storage_r, &error));
		return -1;
	}

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	kw = str_array_length(keywords) == 0 ? NULL :
		mailbox_keywords_create_valid(box, keywords);
	if (mailbox_copy(t, mail, flags, kw, NULL) < 0)
		ret = -1;
	mailbox_keywords_free(box, &kw);

	if (ret < 0)
		mailbox_transaction_rollback(&t);
	else
		ret = mailbox_transaction_commit(&t);

	if (ret == 0) {
		saved_mail = TRUE;
		deliver_log(mail, "saved mail to %s", mailbox_name);
	} else {
		deliver_log(mail, "save failed to %s: %s", mailbox_name,
			    mail_storage_get_last_error(*storage_r, &error));
	}

	mailbox_close(&box);
	return ret;
}

const char *deliver_get_return_address(struct mail *mail)
{
	return deliver_get_address(mail, "Return-Path");
}

const char *deliver_get_new_message_id(void)
{
	static int count = 0;

	return t_strdup_printf("<dovecot-%s-%s-%d@%s>",
			       dec2str(ioloop_timeval.tv_sec),
			       dec2str(ioloop_timeval.tv_usec),
			       count++, deliver_set->hostname);
}

#include "settings.h"
#include "../master/master-settings.h"
#include "../master/master-settings-defs.c"

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

static bool setting_is_bool(const char *name)
{
	const struct setting_def *def;

	for (def = setting_defs; def->name != NULL; def++) {
		if (strcmp(def->name, name) == 0)
			return def->type == SET_BOOL;
	}
	if (strncmp(name, "NAMESPACE_", 10) == 0) {
		return strstr(name, "_list") != NULL ||
			strstr(name, "_inbox") != NULL ||
			strstr(name, "_hidden") != NULL ||
			strstr(name, "_subscriptions") != NULL;
	}
	return FALSE;
}

static void config_file_init(const char *path)
{
	struct istream *input;
	const char *key, *value;
	char *line, *p, quote;
	int fd, sections = 0;
	bool lda_section = FALSE, pop3_section = FALSE, plugin_section = FALSE;
	bool ns_section = FALSE, ns_location = FALSE, ns_list = FALSE;
	bool ns_subscriptions = FALSE;
	unsigned int ns_idx = 0;
	size_t len;

	plugin_pool = pool_alloconly_create("Plugin strings", 512);
	i_array_init(&plugin_envs, 16);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal_status(EX_CONFIG, "open(%s) failed: %m", path);

	input = i_stream_create_fd(fd, 1024, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* @UNSAFE: line is modified */

		/* skip whitespace */
		while (IS_WHITE(*line))
			line++;

		/* ignore comments or empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		/* strip away comments. pretty kludgy way really.. */
		for (p = line; *p != '\0'; p++) {
			if (*p == '\'' || *p == '"') {
				quote = *p;
				for (p++; *p != quote && *p != '\0'; p++) {
					if (*p == '\\' && p[1] != '\0')
						p++;
				}
				if (*p == '\0')
					break;
			} else if (*p == '#') {
				*p = '\0';
				break;
			}
		}

		/* remove whitespace from end of line */
		len = strlen(line);
		while (IS_WHITE(line[len-1]))
			len--;
		line[len] = '\0';

		value = p = strchr(line, '=');
		if (value == NULL) {
			if (strchr(line, '{') != NULL) {
				if (strcmp(line, "protocol lda {") == 0)
					lda_section = TRUE;
				else if (strcmp(line, "plugin {") == 0) {
					plugin_section = TRUE;
					lda_section = TRUE;
				} else if (strcmp(line, "protocol pop3 {") == 0)
					pop3_section = TRUE;
				else if (strncmp(line, "namespace ", 10) == 0) {
					ns_section = TRUE;
					ns_idx++;
					line += 10;
					env_put(t_strdup_printf(
						"NAMESPACE_%u_TYPE=%s", ns_idx,
						t_strcut(line, ' ')));
				}
				sections++;
			}
			if (*line == '}') {
				sections--;
				lda_section = FALSE;
				plugin_section = FALSE;
				pop3_section = FALSE;
				ns_section = FALSE;
				if (ns_location)
					ns_location = FALSE;
				else {
					env_put(t_strdup_printf(
						"NAMESPACE_%u=", ns_idx));
				}
				if (ns_list)
					ns_list = FALSE;
				else {
					env_put(t_strdup_printf(
						"NAMESPACE_%u_LIST=1", ns_idx));
				}
				if (ns_subscriptions)
					ns_subscriptions = FALSE;
				else {
					env_put(t_strdup_printf(
						"NAMESPACE_%u_SUBSCRIPTIONS=1",
						ns_idx));
				}
			}
			continue;
		}

		while (p > line && IS_WHITE(p[-1])) p--;
		key = t_strdup_until(line, p);

		if (sections > 0 && !lda_section) {
			if (pop3_section) {
				if (strcmp(key, "pop3_uidl_format") != 0)
					continue;
			} else if (ns_section) {
				if (strcmp(key, "separator") == 0) {
					key = t_strdup_printf(
						"NAMESPACE_%u_SEP", ns_idx);
				} else if (strcmp(key, "location") == 0) {
					ns_location = TRUE;
					key = t_strdup_printf("NAMESPACE_%u",
							      ns_idx);
				} else {
					if (strcmp(key, "list") == 0)
						ns_list = TRUE;
					if (strcmp(key, "subscriptions") == 0)
						ns_subscriptions = TRUE;
					key = t_strdup_printf("NAMESPACE_%u_%s",
							      ns_idx, key);
				}
			}
		}

		do {
			value++;
		} while (IS_WHITE(*value));

		len = strlen(value);
		if (len > 0 &&
		    ((*value == '"' && value[len-1] == '"') ||
		     (*value == '\'' && value[len-1] == '\''))) {
			value = str_unescape(p_strndup(unsafe_data_stack_pool,
						       value+1, len - 2));
		}
		if (setting_is_bool(key) && strcasecmp(value, "yes") != 0)
			continue;

		if (!plugin_section) {
			env_put(t_strconcat(t_str_ucase(key), "=",
					    value, NULL));
		} else {
			/* %variables need to be expanded.
			   store these for later. */
			value = p_strconcat(plugin_pool,
					    t_str_ucase(key), "=", value, NULL);
			array_append(&plugin_envs, &value, 1);
		}
	}
	i_stream_unref(&input);
}

static const struct var_expand_table *
get_var_expand_table(const char *user, const char *home)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL },
		{ 'n', NULL },
		{ 'd', NULL },
		{ 's', NULL },
		{ 'h', NULL },
		{ 'l', NULL },
		{ 'r', NULL },
		{ 'p', NULL },
		{ 'i', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = user;
	tab[1].value = t_strcut(user, '@');
	tab[2].value = strchr(user, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = "DELIVER";
	tab[4].value = home != NULL ? home :
		"/HOME_DIRECTORY_USED_BUT_NOT_GIVEN_BY_USERDB";
	tab[5].value = NULL;
	tab[6].value = NULL;
	tab[7].value = my_pid;
	tab[8].value = dec2str(geteuid());

	return tab;
}

static const char *
expand_mail_env(const char *env, const struct var_expand_table *table)
{
	string_t *str;
	const char *p;

	str = t_str_new(256);

	/* it's either type:data or just data */
	p = strchr(env, ':');
	if (p != NULL) {
		while (env != p) {
			str_append_c(str, *env);
			env++;
		}

		str_append_c(str, *env++);
	}

	if (env[0] == '~' && env[1] == '/') {
		/* expand home */
		env = t_strconcat("%h", env+1, NULL);
	}

	/* expand %vars */
	var_expand(str, env, table);
	return str_c(str);
}

static const char *escape_local_part(const char *local_part)
{
	const char *p;

	/* if there are non-atext chars, we need to return quoted-string */
	for (p = local_part; *p != '\0'; p++) {
		if (!IS_ATEXT(*p)) {
			return t_strdup_printf("\"%s\"",
					       str_escape(local_part));
		}
	}
	return local_part;
}

static const char *address_sanitize(const char *address)
{
	struct message_address *addr;
	const char *ret, *mailbox;
	pool_t pool;

	pool = pool_alloconly_create("address sanitizer", 256);
	addr = message_address_parse(pool, (const unsigned char *)address,
				     strlen(address), 1, FALSE);

	if (addr == NULL || addr->mailbox == NULL || addr->domain == NULL ||
	    *addr->mailbox == '\0')
		ret = DEFAULT_ENVELOPE_SENDER;
	else {
		mailbox = escape_local_part(addr->mailbox);
		if (*addr->domain == '\0')
			ret = t_strdup(mailbox);
		else
			ret = t_strdup_printf("%s@%s", mailbox, addr->domain);
	}
	pool_unref(&pool);
	return ret;
}


static struct istream *create_raw_stream(int fd, time_t *mtime_r)
{
	struct istream *input, *input2, *input_list[2];
	const unsigned char *data;
	char *sender = NULL;
	size_t i, size;
	int ret;

	*mtime_r = (time_t)-1;
	fd_set_nonblock(fd, FALSE);

	input = i_stream_create_fd(fd, 4096, FALSE);
	input->blocking = TRUE;
	/* If input begins with a From-line, drop it */
	ret = i_stream_read_data(input, &data, &size, 5);
	if (ret > 0 && size >= 5 && memcmp(data, "From ", 5) == 0) {
		/* skip until the first LF */
		i_stream_skip(input, 5);
		while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
			for (i = 0; i < size; i++) {
				if (data[i] == '\n')
					break;
			}
			if (i != size) {
				(void)mbox_from_parse(data, i, mtime_r,
						      &sender);
				i_stream_skip(input, i + 1);
				break;
			}
			i_stream_skip(input, size);
		}
	}

	if (sender != NULL && explicit_envelope_sender == NULL) {
		/* use the envelope sender from From_-line, but only if it
		   hasn't been specified with -f already. */
		explicit_envelope_sender = i_strdup(sender);
	}
	i_free(sender);

	if (input->v_offset == 0) {
		input2 = input;
		i_stream_ref(input2);
	} else {
		input2 = i_stream_create_limit(input, (uoff_t)-1);
	}
	i_stream_unref(&input);

	input_list[0] = input2; input_list[1] = NULL;
	input = i_stream_create_seekable(input_list, MAIL_MAX_MEMORY_BUFFER,
					 "/tmp/dovecot.deliver.");
	i_stream_unref(&input2);
	return input;
}

static void failure_exit_callback(int *status)
{
	/* we want all our exit codes to be sysexits.h compatible */
	switch (*status) {
	case FATAL_LOGOPEN:
	case FATAL_LOGWRITE:
	case FATAL_LOGERROR:
	case FATAL_OUTOFMEM:
	case FATAL_EXEC:
	case FATAL_DEFAULT:
		*status = EX_TEMPFAIL;
		break;
	}
}

static void open_logfile(const char *username)
{
	const char *prefix, *log_path, *stamp;

	prefix = t_strdup_printf("deliver(%s)", username);
	log_path = getenv("LOG_PATH");
	if (log_path == NULL || *log_path == '\0') {
		const char *env = getenv("SYSLOG_FACILITY");
		int facility;

		if (env == NULL || !syslog_facility_find(env, &facility))
			facility = LOG_MAIL;
		i_set_failure_syslog(prefix, LOG_NDELAY, facility);
	} else {
		/* log to file or stderr */
		i_set_failure_file(log_path, t_strconcat(prefix, ": ", NULL));
	}

	log_path = getenv("INFO_LOG_PATH");
	if (log_path != NULL && *log_path != '\0')
		i_set_info_file(log_path);

	stamp = getenv("LOG_TIMESTAMP");
	if (stamp == NULL)
		stamp = DEFAULT_FAILURE_STAMP_FORMAT;
	i_set_failure_timestamp_format(stamp);
}

static void print_help(void)
{
	printf(
"Usage: deliver [-c <config file>] [-a <address>] [-d <username>]\n"
"               [-f <envelope sender>] [-m <mailbox>] [-n] [-e] [-k]\n");
}

void deliver_env_clean(void)
{
	const char *tz, *home;

	tz = getenv("TZ");
	if (tz != NULL)
		tz = t_strconcat("TZ=", tz, NULL);
	home = getenv("HOME");
	if (home != NULL)
		home = t_strconcat("HOME=", home, NULL);

	/* Note that if the original environment was set with env_put(), the
	   environment strings will be invalid after env_clean(). That's why
	   we t_strconcat() them above. */
	env_clean();

	if (tz != NULL) env_put(tz);
	if (home != NULL) env_put(home);
}

static void expand_envs(const char *user)
{
        const struct var_expand_table *table;
	const char *mail_env, *const *envs, *home;
	unsigned int i, count;
	string_t *str;

	home = getenv("HOME");

	str = t_str_new(256);
	table = get_var_expand_table(user, home);
	envs = array_get(&plugin_envs, &count);
	for (i = 0; i < count; i++) {
		str_truncate(str, 0);
		var_expand(str, envs[i], table);
		env_put(str_c(str));
	}

	mail_env = getenv("MAIL_LOCATION");
	if (mail_env != NULL) {
		/* get the table again in case plugin envs provided the home
		   directory (yea, kludgy) */
		if (home == NULL)
			home = getenv("HOME");
		table = get_var_expand_table(user, home);
		mail_env = expand_mail_env(mail_env, table);
	}
	env_put(t_strconcat("MAIL=", mail_env, NULL));
}

static void putenv_extra_fields(ARRAY_TYPE(string) *extra_fields)
{
	char **fields;
	const char *key, *p;
	unsigned int i, count;

	fields = array_get_modifiable(extra_fields, &count);
	for (i = 0; i < count; i++) {
		p = strchr(fields[i], '=');
		if (p == NULL)
			env_put(t_strconcat(fields[i], "=1", NULL));
		else {
			key = t_str_ucase(t_strdup_until(fields[i], p));
			env_put(t_strconcat(key, p, NULL));
		}
		i_free(fields[i]);
	}
}

int main(int argc, char *argv[])
{
	const char *config_path = DEFAULT_CONFIG_FILE;
	const char *mailbox = "INBOX";
	const char *auth_socket;
	const char *home, *destaddr, *user, *value, *errstr;
	ARRAY_TYPE(string) extra_fields;
	struct mail_namespace *ns, *raw_ns;
	struct mail_storage *storage;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct istream *input;
	struct mailbox_transaction_context *t;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail *mail;
	uid_t process_euid;
	pool_t namespace_pool;
	bool stderr_rejection = FALSE;
	bool keep_environment = FALSE;
	bool user_auth = FALSE;
	time_t mtime;
	int i, ret;

	i_set_failure_exit_callback(failure_exit_callback);

	lib_init();
	ioloop = io_loop_create();

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
#ifdef SIGXFSZ
        lib_signals_ignore(SIGXFSZ, TRUE);
#endif

	destaddr = user = NULL;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			/* destination address */
			i++;
			if (i == argc)
				i_fatal_status(EX_USAGE, "Missing -a argument");
			destaddr = argv[i];
		} else if (strcmp(argv[i], "-d") == 0) {
			/* destination user */
			i++;
			if (i == argc)
				i_fatal_status(EX_USAGE, "Missing -d argument");
			user = argv[i];
			user_auth = TRUE;
		} else if (strcmp(argv[i], "-e") == 0) {
			stderr_rejection = TRUE;
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file path */
			i++;
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					"Missing config file path argument");
			}
			config_path = argv[i];
		} else if (strcmp(argv[i], "-k") == 0) {
			keep_environment = TRUE;
		} else if (strcmp(argv[i], "-m") == 0) {
			/* destination mailbox */
			i++;
			if (i == argc)
				i_fatal_status(EX_USAGE, "Missing -m argument");
			/* Ignore -m "". This allows doing -m ${extension}
			   in Postfix to handle user+mailbox */
			if (*argv[i] != '\0')
				mailbox = argv[i];
		} else if (strcmp(argv[i], "-n") == 0) {
			/* destination mailbox */
			no_mailbox_autocreate = TRUE;
		} else if (strcmp(argv[i], "-f") == 0) {
			/* envelope sender address */
			i++;
			if (i == argc)
				i_fatal_status(EX_USAGE, "Missing -f argument");
			explicit_envelope_sender =
				i_strdup(address_sanitize(argv[i]));
		} else if (argv[i][0] != '\0') {
			print_help();
			i_fatal_status(EX_USAGE,
				       "Unknown argument: %s", argv[i]);
		}
	}

	if (user == NULL)
		user = getenv("USER");
	if (!keep_environment)
		deliver_env_clean();

	process_euid = geteuid();
	if (user_auth)
		;
	else if (process_euid != 0) {
		/* we're non-root. get our username and possibly our home. */
		struct passwd *pw;

		home = getenv("HOME");
		if (user != NULL && home != NULL) {
			/* no need for a pw lookup */
		} else if ((pw = getpwuid(process_euid)) != NULL) {
			user = t_strdup(pw->pw_name);
			if (home == NULL)
				env_put(t_strconcat("HOME=", pw->pw_dir, NULL));
		} else if (user == NULL) {
			i_fatal_status(EX_USAGE,
				       "Couldn't lookup our username (uid=%s)",
				       dec2str(process_euid));
		}
	} else {
		i_fatal_status(EX_USAGE,
			"destination user parameter (-d user) not given");
	}

	T_BEGIN {
		config_file_init(config_path);
	} T_END;
	open_logfile(user);

	if (getenv("MAIL_DEBUG") != NULL)
		env_put("DEBUG=1");

	if (getenv("MAIL_PLUGINS") == NULL)
		modules = NULL;
	else {
		const char *plugin_dir = getenv("MAIL_PLUGIN_DIR");
		const char *version;

		if (plugin_dir == NULL)
			plugin_dir = MODULEDIR"/lda";

		version = getenv("VERSION_IGNORE") != NULL ?
			NULL : PACKAGE_VERSION;
		modules = module_dir_load(plugin_dir, getenv("MAIL_PLUGINS"),
					  TRUE, version);
	}

	t_array_init(&extra_fields, 64);
	if (user_auth) {
		auth_socket = getenv("AUTH_SOCKET_PATH");
		if (auth_socket == NULL) {
			const char *base_dir = getenv("BASE_DIR");
			if (base_dir == NULL)
				base_dir = PKG_RUNDIR;
			auth_socket = t_strconcat(base_dir, "/auth-master",
						  NULL);
		}

		ret = auth_client_lookup_and_restrict(ioloop, auth_socket,
						      user, process_euid,
						      &extra_fields);
		if (ret != 0)
			return ret;
	}
	if (destaddr == NULL)
		destaddr = user;

	expand_envs(user);
	putenv_extra_fields(&extra_fields);

	/* Fix namespaces with empty locations */
	for (i = 1;; i++) {
		value = getenv(t_strdup_printf("NAMESPACE_%u", i));
		if (value == NULL)
			break;

		if (*value == '\0') {
			env_put(t_strdup_printf("NAMESPACE_%u=%s", i,
						getenv("MAIL")));
		}
	}

	/* If possible chdir to home directory, so that core file
	   could be written in case we crash. */
	home = getenv("HOME");
	if (home != NULL) {
		if (chdir(home) < 0) {
			if (errno != ENOENT)
				i_error("chdir(%s) failed: %m", home);
			else if (getenv("DEBUG") != NULL)
				i_info("Home dir not found: %s", home);
		}
	}

	env_put(t_strconcat("USER=", user, NULL));

	value = getenv("UMASK");
	if (value == NULL || sscanf(value, "%i", &i) != 1 || i < 0)
		i = 0077;
	(void)umask(i);

	deliver_set = i_new(struct deliver_settings, 1);
	deliver_set->hostname = getenv("HOSTNAME");
	if (deliver_set->hostname == NULL)
		deliver_set->hostname = my_hostname;
	deliver_set->postmaster_address = getenv("POSTMASTER_ADDRESS");
	if (deliver_set->postmaster_address == NULL) {
		i_fatal_status(EX_CONFIG,
			       "postmaster_address setting not given");
	}
	deliver_set->sendmail_path = getenv("SENDMAIL_PATH");
	if (deliver_set->sendmail_path == NULL)
		deliver_set->sendmail_path = DEFAULT_SENDMAIL_PATH;
	deliver_set->rejection_reason = getenv("REJECTION_REASON");
	if (deliver_set->rejection_reason == NULL) {
		deliver_set->rejection_reason =
			DEFAULT_MAIL_REJECTION_HUMAN_REASON;
	}
	deliver_set->log_format = getenv("DELIVER_LOG_FORMAT");
	if (deliver_set->log_format == NULL)
		deliver_set->log_format = DEFAULT_LOG_FORMAT;

	dict_driver_register(&dict_driver_client);
        duplicate_init();
        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	module_dir_init(modules);

	namespace_pool = pool_alloconly_create("namespaces", 1024);
	if (mail_namespaces_init(namespace_pool, user, &ns) < 0)
		i_fatal("Namespace initialization failed");

	raw_ns = mail_namespaces_init_empty(namespace_pool);
	raw_ns->flags |= NAMESPACE_FLAG_INTERNAL;
	if (mail_storage_create(raw_ns, "raw", "/tmp", user,
				0, FILE_LOCK_METHOD_FCNTL, &errstr) < 0)
		i_fatal("Couldn't create internal raw storage: %s", errstr);
	input = create_raw_stream(0, &mtime);
	box = mailbox_open(raw_ns->storage, "Dovecot Delivery Mail", input,
			   MAILBOX_OPEN_NO_INDEX_FILES);
	if (box == NULL)
		i_fatal("Can't open delivery mail as raw");
	if (mailbox_sync(box, 0, 0, NULL) < 0) {
		enum mail_error error;

		i_fatal("Can't sync delivery mail: %s",
			mail_storage_get_last_error(raw_ns->storage, &error));
	}
	raw_box = (struct raw_mailbox *)box;
	raw_box->envelope_sender = explicit_envelope_sender != NULL ?
		explicit_envelope_sender : DEFAULT_ENVELOPE_SENDER;
	raw_box->mtime = mtime;

	t = mailbox_transaction_begin(box, 0);
	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	mail = mail_alloc(t, 0, headers_ctx);
	mail_set_seq(mail, 1);

	storage = NULL;
	default_mailbox_name = mailbox;
	if (deliver_mail == NULL)
		ret = -1;
	else {
		if (deliver_mail(ns, &storage, mail, destaddr, mailbox) <= 0) {
			/* if message was saved, don't bounce it even though
			   the script failed later. */
			ret = saved_mail ? 0 : -1;
		} else {
			/* success. message may or may not have been saved. */
			ret = 0;
		}
	}

	if (ret < 0 && !tried_default_save) {
		/* plugins didn't handle this. save into the default mailbox. */
		i_stream_seek(input, 0);
		ret = deliver_save(ns, &storage, mailbox, mail, 0, NULL);
	}
	if (ret < 0 && strcasecmp(mailbox, "INBOX") != 0) {
		/* still didn't work. try once more to save it
		   to INBOX. */
		i_stream_seek(input, 0);
		ret = deliver_save(ns, &storage, "INBOX", mail, 0, NULL);
	}

	if (ret < 0 ) {
		const char *error_string;
		enum mail_error error;

		if (storage == NULL) {
			/* This shouldn't happen */
			i_error("BUG: Saving failed for unknown storage");
			return EX_TEMPFAIL;
		}

		error_string = mail_storage_get_last_error(storage, &error);

		if (stderr_rejection) {
			/* write to stderr also for tempfails so that MTA
			   can log the reason if it wants to. */
			fprintf(stderr, "%s\n", error_string);
		}

		if (error != MAIL_ERROR_NOSPACE ||
		    getenv("QUOTA_FULL_TEMPFAIL") != NULL) {
			/* Saving to INBOX should always work unless
			   we're over quota. If it didn't, it's probably a
			   configuration problem. */
			return EX_TEMPFAIL;
		}

		/* we'll have to reply with permanent failure */
		deliver_log(mail, "rejected: %s",
			    str_sanitize(error_string, 512));

		if (stderr_rejection)
			return EX_NOPERM;
		ret = mail_send_rejection(mail, user, error_string);
		if (ret != 0)
			return ret < 0 ? EX_TEMPFAIL : ret;
		/* ok, rejection sent */
	}
	i_stream_unref(&input);
	i_free(explicit_envelope_sender);

	mail_free(&mail);
	mailbox_header_lookup_deinit(&headers_ctx);
	mailbox_transaction_rollback(&t);
	mailbox_close(&box);

	mail_namespaces_deinit(&raw_ns);
	mail_namespaces_deinit(&ns);

	module_dir_unload(&modules);
	mail_storage_deinit();

	duplicate_deinit();
	dict_driver_unregister(&dict_driver_client);
	lib_signals_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

        return EX_OK;
}
