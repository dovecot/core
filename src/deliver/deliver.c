/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"
#include "file-lock.h"
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
#include "message-address.h"
#include "istream-header-filter.h"
#include "mbox-storage.h"
#include "mail-namespace.h"
#include "dict-client.h"
#include "mbox-from.h"
#include "auth-client.h"
#include "mail-send.h"
#include "duplicate.h"
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
#define DEFAULT_AUTH_SOCKET_PATH PKG_RUNDIR"/auth-master"
#define DEFAULT_SENDMAIL_PATH "/usr/lib/sendmail"
#define DEFAULT_ENVELOPE_SENDER "MAILER-DAEMON"

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
#define MAIL_MAX_MEMORY_BUFFER (1024*128)

struct deliver_settings *deliver_set;
deliver_mail_func_t *deliver_mail = NULL;

/* FIXME: these two should be in some context struct instead of as globals.. */
static const char *default_mailbox_name = NULL;
static bool tried_default_save = FALSE;
static bool no_mailbox_autocreate = FALSE;

static struct module *modules;
static struct ioloop *ioloop;

static void sig_die(int signo, void *context __attr_unused__)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static int sync_quick(struct mailbox *box)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;

	ctx = mailbox_sync_init(box, 0);
	while (mailbox_sync_next(ctx, &sync_rec) > 0)
		;
	return mailbox_sync_deinit(&ctx, 0, NULL);
}

static struct mailbox *
mailbox_open_or_create_synced(struct mail_namespace *namespaces,
			      struct mail_storage **storage_r, const char *name)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	bool temp;

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

	(void)mail_storage_get_last_error(ns->storage, &temp);
	if (temp)
		return NULL;

	/* probably the mailbox just doesn't exist. try creating it. */
	if (mail_storage_mailbox_create(ns->storage, name, FALSE) < 0)
		return NULL;

	/* and try opening again */
	box = mailbox_open(ns->storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	if (box == NULL)
		return NULL;

	if (sync_quick(box) < 0) {
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
	const char *msgid;
	int ret = 0;

	if (strcmp(mailbox, default_mailbox_name) == 0)
		tried_default_save = TRUE;

	box = mailbox_open_or_create_synced(namespaces, storage_r, mailbox);
	if (box == NULL)
		return -1;

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	kw = strarray_length(keywords) == 0 ? NULL :
		mailbox_keywords_create(t, keywords);
	if (mailbox_copy(t, mail, flags, kw, NULL) < 0)
		ret = -1;
	mailbox_keywords_free(t, &kw);

	if (ret < 0)
		mailbox_transaction_rollback(&t);
	else
		ret = mailbox_transaction_commit(&t, 0);

	msgid = mail_get_first_header(mail, "Message-ID");
	i_info(ret < 0 ? "msgid=%s: save failed to %s" :
	       "msgid=%s: saved mail to %s",
	       msgid == NULL ? "" : str_sanitize(msgid, 80),
	       str_sanitize(mailbox_get_name(box), 80));

	mailbox_close(&box);
	return ret;
}

const char *deliver_get_return_address(struct mail *mail)
{
	struct message_address *addr;
	const char *str;

	str = mail_get_first_header(mail, "Return-Path");
	addr = str == NULL ? NULL :
		message_address_parse(pool_datastack_create(),
				      (const unsigned char *)str,
				      strlen(str), 1, FALSE);
	return addr == NULL || addr->mailbox == NULL || addr->domain == NULL ?
		NULL : t_strconcat(addr->mailbox, "@", addr->domain, NULL);
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
	return FALSE;
}

static void config_file_init(const char *path)
{
	struct istream *input;
	const char *key, *value;
	char *line, *p, quote;
	int fd, sections = 0, lda_section = FALSE, pop3_section = FALSE;
	size_t len;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal_status(EX_CONFIG, "open(%s) failed: %m", path);

	t_push();
	input = i_stream_create_file(fd, default_pool, 1024, TRUE);
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
				if (strcmp(line, "protocol lda {") == 0 ||
				    strcmp(line, "plugin {") == 0)
					lda_section = TRUE;
				if (strcmp(line, "protocol pop3 {") == 0)
					pop3_section = TRUE;
				sections++;
			}
			if (*line == '}') {
				sections--;
				lda_section = FALSE;
				pop3_section = FALSE;
			}
			continue;
		}

		while (p > line && p[-1] == ' ') p--;
		key = t_strdup_until(line, p);

		if (sections > 0 && !lda_section) {
			if (!pop3_section ||
			    strcmp(key, "pop3_uidl_format") != 0)
				continue;
		}

		do {
			value++;
		} while (*value == ' ');

		len = strlen(value);
		if (len > 0 &&
		    ((*value == '"' && value[len-1] == '"') ||
		     (*value == '\'' && value[len-1] == '\''))) {
			value = str_unescape(p_strndup(unsafe_data_stack_pool,
						       value+1, len - 2));
		}
		if (setting_is_bool(key) && strcasecmp(value, "yes") != 0)
			continue;

		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	}
	i_stream_unref(&input);
	t_pop();
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

static const char *address_sanitize(const char *address)
{
	struct message_address *addr;
	const char *ret;
	pool_t pool;

	pool = pool_alloconly_create("address sanitizer", 256);
	addr = message_address_parse(pool, (const unsigned char *)address,
				     strlen(address), 1, FALSE);

	if (addr == NULL || addr->mailbox == NULL || addr->domain == NULL ||
	    *addr->mailbox == '\0')
		ret = DEFAULT_ENVELOPE_SENDER;
	else if (*addr->domain == '\0')
		ret = t_strdup(addr->mailbox);
	else
		ret = t_strdup_printf("%s@%s", addr->mailbox, addr->domain);
	pool_unref(pool);
	return ret;
}

static struct istream *create_mbox_stream(int fd, const char *envelope_sender)
{
	const char *mbox_hdr;
	struct istream *input_list[4], *input, *input_filter;

	fd_set_nonblock(fd, FALSE);

	envelope_sender = address_sanitize(envelope_sender);
	mbox_hdr = mbox_from_create(envelope_sender, ioloop_time);

	input = i_stream_create_file(fd, default_pool, 4096, FALSE);
	input_filter =
		i_stream_create_header_filter(input,
					      HEADER_FILTER_EXCLUDE |
					      HEADER_FILTER_NO_CR,
					      mbox_hide_headers,
					      mbox_hide_headers_count,
					      null_header_filter_callback,
					      NULL);
	i_stream_unref(&input);

	input_list[0] = i_stream_create_from_data(default_pool, mbox_hdr,
						  strlen(mbox_hdr));
	input_list[1] = input_filter;
	input_list[2] = i_stream_create_from_data(default_pool, "\n", 1);
	input_list[3] = NULL;

	input = i_stream_create_seekable(input_list, default_pool,
					 MAIL_MAX_MEMORY_BUFFER,
					 "/tmp/dovecot.deliver.");
	i_stream_unref(&input_list[0]);
	i_stream_unref(&input_list[1]);
	i_stream_unref(&input_list[2]);
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
"Usage: deliver [-c <config file>] [-d <destination user>] [-m <mailbox>]\n"
"               [-n] [-e] [-f <envelope sender>]\n");
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

int main(int argc, char *argv[])
{
	const char *config_path = DEFAULT_CONFIG_FILE;
	const char *envelope_sender = DEFAULT_ENVELOPE_SENDER;
	const char *mailbox = "INBOX";
	const char *auth_socket;
	const char *home, *destination, *user, *mail_env, *value;
        const struct var_expand_table *table;
	struct mail_namespace *ns, *mbox_ns;
	struct mail_storage *storage;
	struct mailbox *box;
	struct istream *input;
	struct mailbox_transaction_context *t;
	struct mail *mail;
	uid_t process_euid;
	pool_t namespace_pool;
	bool stderr_rejection = FALSE;
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

	deliver_env_clean();

	destination = NULL;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			/* destination user */
			i++;
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					       "Missing destination argument");
			}
			destination = argv[i];
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
		} else if (strcmp(argv[i], "-m") == 0) {
			/* destination mailbox */
			i++;
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					       "Missing mailbox argument");
			}
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
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					       "Missing envelope argument");
			}
			envelope_sender = argv[i];
		} else if (argv[i][0] != '\0') {
			print_help();
			i_fatal_status(EX_USAGE,
				       "Unknown argument: %s", argv[i]);
		}
	}

	process_euid = geteuid();
	if (destination != NULL)
		user = destination;
	else if (process_euid != 0) {
		/* we're non-root. get our username and possibly our home. */
		struct passwd *pw;

		pw = getpwuid(process_euid);
		if (pw != NULL) {
			user = t_strdup(pw->pw_name);
			if (getenv("HOME") == NULL)
				env_put(t_strconcat("HOME=", pw->pw_dir, NULL));
		} else {
			i_fatal("Couldn't lookup our username (uid=%s)",
				dec2str(process_euid));
		}
	} else {
		i_fatal_status(EX_USAGE,
			"destination user parameter (-d user) not given");
	}

	config_file_init(config_path);
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

	if (destination != NULL) {
		auth_socket = getenv("AUTH_SOCKET_PATH");
		if (auth_socket == NULL)
			auth_socket = DEFAULT_AUTH_SOCKET_PATH;

		ret = auth_client_put_user_env(ioloop, auth_socket,
					       destination, process_euid);
		if (ret != 0)
			return ret;

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
	} else {
		destination = user;
	}

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

	dict_driver_register(&dict_driver_client);
        duplicate_init();
        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	/* MAIL comes from userdb, MAIL_LOCATION from dovecot.conf.
	   FIXME: should remove these and support namespaces.. */
	mail_env = getenv("MAIL");
	if (mail_env == NULL) 
		mail_env = getenv("MAIL_LOCATION");
	if (mail_env == NULL)  {
		/* Keep this for backwards compatibility */
		mail_env = getenv("DEFAULT_MAIL_ENV");
	}
	if (mail_env != NULL) {
		table = get_var_expand_table(destination, getenv("HOME"));
		mail_env = expand_mail_env(mail_env, table);
	}
	env_put(t_strconcat("MAIL=", mail_env, NULL));

	module_dir_init(modules);

	namespace_pool = pool_alloconly_create("namespaces", 1024);
	if (mail_namespaces_init(namespace_pool, destination, &ns) < 0)
		exit(EX_TEMPFAIL);

	mbox_ns = mail_namespaces_init_empty(namespace_pool);
	if (mail_storage_create(mbox_ns, "mbox", "/tmp", destination,
				0, FILE_LOCK_METHOD_FCNTL) < 0)
		i_fatal("Couldn't create internal mbox storage");
	input = create_mbox_stream(0, envelope_sender);
	box = mailbox_open(mbox_ns->storage, "Dovecot Delivery Mail", input,
			   MAILBOX_OPEN_NO_INDEX_FILES |
			   MAILBOX_OPEN_MBOX_ONE_MSG_ONLY);
	if (box == NULL)
		i_fatal("Can't open delivery mail as mbox");
        if (sync_quick(box) < 0)
		i_fatal("Can't sync delivery mail");

	t = mailbox_transaction_begin(box, 0);
	mail = mail_alloc(t, 0, NULL);
	if (mail_set_seq(mail, 1) < 0)
		i_fatal("mail_set_seq() failed");

	default_mailbox_name = mailbox;
	ret = deliver_mail == NULL ? 0 :
		deliver_mail(ns, &storage, mail, destination, mailbox);

	if (ret == 0 || (ret < 0 && !tried_default_save)) {
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

	if (ret < 0) {
		const char *error, *msgid;
		bool temporary_error;
		int ret;

		error = mail_storage_get_last_error(storage, &temporary_error);
		if (temporary_error)
			return EX_TEMPFAIL;

		msgid = mail_get_first_header(mail, "Message-ID");
		i_info("msgid=%s: Rejected: %s",
		       msgid == NULL ? "" : str_sanitize(msgid, 80),
		       str_sanitize(error, 512));

		/* we'll have to reply with permanent failure */
		if (stderr_rejection) {
			fprintf(stderr, "%s\n", error);
			return EX_NOPERM;
		}
		ret = mail_send_rejection(mail, destination, error);
		if (ret != 0)
			return ret < 0 ? EX_TEMPFAIL : ret;
		/* ok, rejection sent */
	}
	i_stream_unref(&input);

	mail_free(&mail);
	mailbox_transaction_rollback(&t);
	mailbox_close(&box);

	mail_namespaces_deinit(&mbox_ns);
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
