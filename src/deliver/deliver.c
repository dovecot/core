/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

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
#include "imap-utf7.h"
#include "settings-parser.h"
#include "dict.h"
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
bool mailbox_autosubscribe;
bool mailbox_autocreate;
bool tried_default_save = FALSE;

/* FIXME: these two should be in some context struct instead of as globals.. */
static const char *default_mailbox_name = NULL;
static bool saved_mail = FALSE;
static char *explicit_envelope_sender = NULL;

static struct module *modules;
static struct ioloop *ioloop;

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(current_ioloop);
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
		{ '$', NULL, NULL },
		{ 'm', NULL, "msgid" },
		{ 's', NULL, "subject" },
		{ 'f', NULL, "from" },
		{ '\0', NULL, NULL }
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
	var_expand(str, deliver_set->deliver_log_format,
		   get_log_var_expand_table(mail, msg));
	i_info("%s", str_c(str));
	va_end(args);
}

static struct mailbox *
mailbox_open_or_create_synced(struct mail_namespace *namespaces,
			      struct mail_storage **storage_r,
			      const char *name)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error error;
	enum mailbox_open_flags open_flags = MAILBOX_OPEN_FAST |
		MAILBOX_OPEN_KEEP_RECENT | MAILBOX_OPEN_SAVEONLY |
		MAILBOX_OPEN_POST_SESSION;

	if (strcasecmp(name, "INBOX") == 0) {
		/* deliveries to INBOX must always succeed,
		   regardless of ACLs */
		open_flags |= MAILBOX_OPEN_IGNORE_ACLS;
	}

	ns = mail_namespace_find(namespaces, &name);
	if (ns == NULL) {
		*storage_r = NULL;
		return NULL;
	}
	*storage_r = ns->storage;

	if (*name == '\0') {
		/* delivering to a namespace prefix means we actually want to
		   deliver to the INBOX instead */
		return NULL;
	}

	box = mailbox_open(storage_r, name, NULL, open_flags);
	if (box != NULL || !mailbox_autocreate)
		return box;

	(void)mail_storage_get_last_error(*storage_r, &error);
	if (error != MAIL_ERROR_NOTFOUND)
		return NULL;

	/* try creating it. */
	if (mail_storage_mailbox_create(*storage_r, name, FALSE) < 0)
		return NULL;
	if (mailbox_autosubscribe) {
		/* (try to) subscribe to it */
		(void)mailbox_list_set_subscribed(ns->list, name, TRUE);
	}

	/* and try opening again */
	box = mailbox_open(storage_r, name, NULL, open_flags);
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
	bool default_save;
	int ret = 0;

	default_save = strcmp(mailbox, default_mailbox_name) == 0;
	if (default_save)
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
		if (default_save &&
		    strcmp((*storage_r)->ns->prefix, mailbox) == 0) {
			/* silently store to the INBOX instead */
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
	int ret, tz;

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
				(void)mbox_from_parse(data, i, mtime_r, &tz,
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
	/* we want all our exit codes to be sysexits.h compatible.
	   if we failed because of a logging related error, we most likely
	   aren't writing to stderr, so try writing there to give some kind of
	   a clue what's wrong. FATAL_LOGOPEN failure already wrote to
	   stderr, so don't duplicate it. */
	switch (*status) {
	case FATAL_LOGWRITE:
		fputs("Failed to write to log file", stderr);
		break;
	case FATAL_LOGERROR:
		fputs("Internal logging error", stderr);
		break;
	case FATAL_LOGOPEN:
	case FATAL_OUTOFMEM:
	case FATAL_EXEC:
	case FATAL_DEFAULT:
		break;
	default:
		return;
	}
	*status = EX_TEMPFAIL;
}

static void open_logfile(const char *username)
{
	const char *prefix, *log_path;

	prefix = t_strdup_printf("deliver(%s): ", username);
	log_path = home_expand(deliver_set->log_path);
	if (*log_path == '\0') {
		int facility;

		if (!syslog_facility_find(deliver_set->syslog_facility,
					  &facility))
			facility = LOG_MAIL;
		i_set_failure_prefix(prefix);
		i_set_failure_syslog("dovecot", LOG_NDELAY, facility);
	} else {
		/* log to file or stderr */
		i_set_failure_file(log_path, prefix);
	}

	log_path = home_expand(deliver_set->info_log_path);
	if (*log_path != '\0')
		i_set_info_file(log_path);

	i_set_failure_timestamp_format(deliver_set->log_timestamp);
}

static void print_help(void)
{
	printf(
"Usage: deliver [-c <config file>] [-a <address>] [-d <username>] [-p <path>]\n"
"               [-f <envelope sender>] [-m <mailbox>] [-n] [-s] [-e] [-k]\n");
}

void deliver_env_clean(bool preserve_home)
{
	const char *tz, *home;

	tz = getenv("TZ");
	if (tz != NULL)
		tz = t_strconcat("TZ=", tz, NULL);
	home = preserve_home ? getenv("HOME") : NULL;
	if (home != NULL)
		home = t_strconcat("HOME=", home, NULL);

	/* Note that if the original environment was set with env_put(), the
	   environment strings will be invalid after env_clean(). That's why
	   we t_strconcat() them above. */
	env_clean();

	if (tz != NULL) env_put(tz);
	if (home != NULL) env_put(home);
}

static void plugin_get_home(void)
{
	const char *const *envs;
	unsigned int i, count;

	/* kludgy. this should be removed some day, but for now don't break
	   existing setups that rely on it. */
	if (array_is_created(&deliver_set->plugin_envs)) {
		envs = array_get(&deliver_set->plugin_envs, &count);
		for (i = 0; i < count; i++) {
			if (strncmp(envs[i], "home=", 5) == 0) {
				env_put(t_strconcat("HOME=", envs[i]+5, NULL));
				break;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	const char *config_path = DEFAULT_CONFIG_FILE;
	const char *mailbox = "INBOX";
	const char *home, *destaddr, *user, *error, *path, *orig_user;
	ARRAY_TYPE(const_string) extra_fields = ARRAY_INIT;
	struct setting_parser_context *parser;
	struct mail_user *mail_user, *raw_mail_user;
	struct mail_namespace *raw_ns;
	struct mail_namespace_settings raw_ns_set;
	struct mail_storage *storage;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct istream *input;
	struct mailbox_transaction_context *t;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	struct mail *mail;
	uid_t process_euid;
	bool stderr_rejection = FALSE;
	bool keep_environment = FALSE;
	bool user_auth = FALSE;
	time_t mtime;
	int i, ret;
	pool_t userdb_pool = NULL;
	string_t *str;

	if (getuid() != geteuid() && geteuid() == 0) {
		/* running setuid - don't allow this if deliver is
		   executable by anyone */
		struct stat st;

		if (stat(argv[0], &st) < 0) {
			fprintf(stderr, "stat(%s) failed: %s\n",
				argv[0], strerror(errno));
			return EX_CONFIG;
		} else if ((st.st_mode & 1) != 0) {
			fprintf(stderr, "%s must not be both world-executable "
				"and setuid-root. This allows root exploits. "
				"See http://wiki.dovecot.org/LDA#multipleuids\n",
				argv[0]);
			return EX_CONFIG;
		}
	}

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

	deliver_set = i_new(struct deliver_settings, 1);
	mailbox_autocreate = TRUE;

	destaddr = user = path = NULL;
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
		} else if (strcmp(argv[i], "-p") == 0) {
			/* input path */
			i++;
			if (i == argc)
				i_fatal_status(EX_USAGE, "Missing -p argument");
			path = argv[i];
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
			if (*argv[i] != '\0') {
				str = t_str_new(256);
				if (imap_utf8_to_utf7(argv[i], str) < 0) {
					i_fatal("Mailbox name not UTF-8: %s",
						mailbox);
				}
				mailbox = str_c(str);
			}
		} else if (strcmp(argv[i], "-n") == 0) {
			mailbox_autocreate = FALSE;
		} else if (strcmp(argv[i], "-s") == 0) {
			mailbox_autosubscribe = TRUE;
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
		deliver_env_clean(!user_auth);

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

        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	parser = deliver_settings_read(config_path, &deliver_set, &user_set);
	open_logfile(user);

	mail_set = mail_user_set_get_driver_settings(user_set, "MAIL");
	if (deliver_set->mail_plugins == '\0')
		modules = NULL;
	else {
		const char *version;

		version = deliver_set->version_ignore ? NULL : PACKAGE_VERSION;
		modules = module_dir_load(deliver_set->mail_plugin_dir,
					  deliver_set->mail_plugins,
					  TRUE, version);
	}

	if (user_auth) {
		userdb_pool = pool_alloconly_create("userdb lookup replys", 512);
		orig_user = user;
		ret = auth_client_lookup_and_restrict(deliver_set->auth_socket_path,
						      &user, process_euid,
						      userdb_pool,
						      &extra_fields);
		if (ret != 0)
			return ret;

		if (strcmp(user, orig_user) != 0) {
			/* auth lookup changed the user. */
			if (mail_set->mail_debug)
				i_info("userdb changed username to %s", user);
			i_set_failure_prefix(t_strdup_printf("deliver(%s): ",
							     user));
		}
		/* if user was changed, it was allocated from userdb_pool
		   which we'll free soon. */
		user = t_strdup(user);
	}

	if (userdb_pool != NULL) {
		settings_parse_set_expanded(parser, TRUE);
		deliver_settings_add(parser, &extra_fields);
		pool_unref(&userdb_pool);
	}

	home = getenv("HOME");
	if (home == NULL) {
		plugin_get_home();
		home = getenv("HOME");
	}

	/* If possible chdir to home directory, so that core file
	   could be written in case we crash. */
	if (home != NULL) {
		if (chdir(home) < 0) {
			if (errno != ENOENT)
				i_error("chdir(%s) failed: %m", home);
			else if (mail_set->mail_debug)
				i_info("Home dir not found: %s", home);
		}
	}

	env_put(t_strconcat("USER=", user, NULL));
	(void)umask(deliver_set->umask);

	dict_drivers_register_builtin();
        duplicate_init();
	mail_users_init(deliver_set->auth_socket_path, mail_set->mail_debug);

	module_dir_init(modules);

	mail_user = mail_user_alloc(user, user_set);
	mail_user_set_home(mail_user, home);
	mail_user_set_vars(mail_user, geteuid(), "deliver", NULL, NULL);
	if (mail_user_init(mail_user, &error) < 0)
		i_fatal("Mail user initialization failed: %s", error);
	if (mail_namespaces_init(mail_user, &error) < 0)
		i_fatal("Namespace initialization failed: %s", error);

	/* create a separate mail user for the internal namespace */
	raw_mail_user = mail_user_alloc(user, user_set);
	mail_user_set_home(raw_mail_user, "/");
	if (mail_user_init(raw_mail_user, &error) < 0)
		i_fatal("Raw user initialization failed: %s", error);

	settings_parser_deinit(&parser);

	memset(&raw_ns_set, 0, sizeof(raw_ns_set));
	raw_ns_set.location = "/tmp";

	raw_ns = mail_namespaces_init_empty(raw_mail_user);
	raw_ns->flags |= NAMESPACE_FLAG_INTERNAL;
	raw_ns->set = &raw_ns_set;
	if (mail_storage_create(raw_ns, "raw", 0, &error) < 0)
		i_fatal("Couldn't create internal raw storage: %s", error);
	if (path == NULL) {
		input = create_raw_stream(0, &mtime);
		box = mailbox_open(&raw_ns->storage, "Dovecot Delivery Mail",
				   input, MAILBOX_OPEN_NO_INDEX_FILES);
		i_stream_unref(&input);
	} else {
		mtime = (time_t)-1;
		box = mailbox_open(&raw_ns->storage, path, NULL,
				   MAILBOX_OPEN_NO_INDEX_FILES);
	}
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

	if (destaddr == NULL) {
		destaddr = deliver_get_address(mail, "Envelope-To");
		if (destaddr == NULL) {
			destaddr = strchr(user, '@') == NULL ? user :
				t_strconcat(user, "@",
					    deliver_set->hostname, NULL);
		}
	}

	storage = NULL;
	default_mailbox_name = mailbox;
	if (deliver_mail == NULL)
		ret = -1;
	else {
		if (deliver_mail(mail_user->namespaces, &storage, mail,
				 destaddr, mailbox) <= 0) {
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
		ret = deliver_save(mail_user->namespaces,
				   &storage, mailbox, mail, 0, NULL);
	}
	if (ret < 0 && strcasecmp(mailbox, "INBOX") != 0) {
		/* still didn't work. try once more to save it
		   to INBOX. */
		ret = deliver_save(mail_user->namespaces,
				   &storage, "INBOX", mail, 0, NULL);
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
		    deliver_set->quota_full_tempfail) {
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
	i_free(explicit_envelope_sender);

	mail_free(&mail);
	mailbox_header_lookup_unref(&headers_ctx);
	mailbox_transaction_rollback(&t);
	mailbox_close(&box);

	mail_user_unref(&mail_user);
	mail_user_unref(&raw_mail_user);

	module_dir_unload(&modules);
	mail_storage_deinit();
	mail_users_deinit();

	duplicate_deinit();
	dict_drivers_unregister_builtin();
	lib_signals_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

        return EX_OK;
}
