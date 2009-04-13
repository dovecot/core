/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "env-util.h"
#include "fd-set-nonblock.h"
#include "istream.h"
#include "istream-seekable.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "var-expand.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "imap-utf7.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "raw-storage.h"
#include "mail-send.h"
#include "duplicate.h"
#include "mbox-from.h"
#include "deliver.h"

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>

#define DEFAULT_ENVELOPE_SENDER "MAILER-DAEMON"

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
#define MAIL_MAX_MEMORY_BUFFER (1024*128)

static const char *wanted_headers[] = {
	"From", "Message-ID", "Subject", "Return-Path",
	NULL
};

const struct deliver_settings *deliver_set;
deliver_mail_func_t *deliver_mail = NULL;
bool mailbox_autosubscribe;
bool mailbox_autocreate;
bool tried_default_save = FALSE;

/* FIXME: these two should be in some context struct instead of as globals.. */
static const char *default_mailbox_name = NULL;
static bool saved_mail = FALSE;
static char *explicit_envelope_sender = NULL;

static struct master_service *service;

static const char *deliver_get_address(struct mail *mail, const char *header)
{
	struct message_address *addr;
	const char *str;

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
	struct mail_save_context *save_ctx;
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
	save_ctx = mailbox_save_alloc(t);
	mailbox_save_set_flags(save_ctx, flags, kw);
	if (mailbox_copy(&save_ctx, mail) < 0)
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
	if (explicit_envelope_sender != NULL)
		return explicit_envelope_sender;

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


static struct istream *
create_raw_stream(const char *temp_path_prefix, int fd, time_t *mtime_r)
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
					 temp_path_prefix);
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

static void print_help(void)
{
	printf(
"Usage: deliver [-c <config file>] [-a <address>] [-d <username>] [-p <path>]\n"
"               [-f <envelope sender>] [-m <mailbox>] [-n] [-s] [-e] [-k]\n");
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags service_flags = 0;
	const char *mailbox = "INBOX";
	const char *destaddr, *user, *errstr, *path, *getopt_str;
	struct mail_user *mail_user, *raw_mail_user;
	struct mail_namespace *raw_ns;
	struct mail_namespace_settings raw_ns_set;
	struct mail_storage *storage;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct istream *input;
	struct mailbox_transaction_context *t;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail *mail;
	char cwd[PATH_MAX];
	void **sets;
	uid_t process_euid;
	bool stderr_rejection = FALSE;
	time_t mtime;
	int ret, c;
	string_t *str;
	enum mail_error error;

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

	service = master_service_init("lda", MASTER_SERVICE_FLAG_STANDALONE,
				      argc, argv);
#ifdef SIGXFSZ
        lib_signals_ignore(SIGXFSZ, TRUE);
#endif

	mailbox_autocreate = TRUE;
	destaddr = path = NULL;

	user = getenv("USER");
	getopt_str = t_strconcat("a:d:p:ekm:nsf:",
				 master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'a':
			/* destination address */
			destaddr = optarg;
			break;
		case 'd':
			/* destination user */
			user = optarg;
			service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			break;
		case 'p':
			/* input path */
			path = optarg;
			if (*path != '/') {
				/* expand relative paths before we chdir */
				if (getcwd(cwd, sizeof(cwd)) == NULL)
					i_fatal("getcwd() failed: %m");
				path = t_strconcat(cwd, "/", path, NULL);
			}
			break;
		case 'e':
			stderr_rejection = TRUE;
			break;
		case 'm':
			/* destination mailbox.
			   Ignore -m "". This allows doing -m ${extension}
			   in Postfix to handle user+mailbox */
			if (*optarg != '\0') {
				str = t_str_new(256);
				if (imap_utf8_to_utf7(optarg, str) < 0) {
					i_fatal("Mailbox name not UTF-8: %s",
						mailbox);
				}
				mailbox = str_c(str);
			}
			break;
		case 'n':
			mailbox_autocreate = FALSE;
			break;
		case 's':
			mailbox_autosubscribe = TRUE;
			break;
		case 'f':
			/* envelope sender address */
			explicit_envelope_sender =
				i_strdup(address_sanitize(optarg));
			break;
		default:
			if (!master_service_parse_option(service, c, optarg)) {
				print_help();
				i_fatal_status(EX_USAGE,
					       "Unknown argument: %c", c);
			}
			break;
		}
	}
	if (optind != argc) {
		print_help();
		i_fatal_status(EX_USAGE, "Unknown argument: %s", argv[optind]);
	}

	process_euid = geteuid();
	if ((service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0)
		;
	else if (process_euid != 0) {
		/* we're non-root. get our username and possibly our home. */
		struct passwd *pw;
		const char *home;

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

	service_flags |= MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;
	mail_user = mail_storage_service_init_user(service, user,
				&deliver_setting_parser_info, service_flags);
	deliver_set = mail_storage_service_get_settings(service);
        duplicate_init(mail_user_set_get_storage_set(mail_user->set));

	/* create a separate mail user for the internal namespace */
	if (master_service_set(service, "mail_full_filesystem_access=yes") < 0)
		i_unreached();
	sets = master_service_settings_get_others(service);
	raw_mail_user = mail_user_alloc(user, sets[0]);
	mail_user_set_home(raw_mail_user, "/");
	if (mail_user_init(raw_mail_user, &errstr) < 0)
		i_fatal("Raw user initialization failed: %s", errstr);

	memset(&raw_ns_set, 0, sizeof(raw_ns_set));
	raw_ns_set.location = "/tmp";

	raw_ns = mail_namespaces_init_empty(raw_mail_user);
	raw_ns->flags |= NAMESPACE_FLAG_INTERNAL;
	raw_ns->set = &raw_ns_set;
	if (mail_storage_create(raw_ns, "raw", 0, &errstr) < 0)
		i_fatal("Couldn't create internal raw storage: %s", errstr);
	if (path == NULL) {
		const char *prefix = mail_user_get_temp_prefix(mail_user);
		input = create_raw_stream(prefix, 0, &mtime);
		box = mailbox_open(&raw_ns->storage, "Dovecot Delivery Mail",
				   input, MAILBOX_OPEN_NO_INDEX_FILES);
		i_stream_unref(&input);
	} else {
		mtime = (time_t)-1;
		box = mailbox_open(&raw_ns->storage, path, NULL,
				   MAILBOX_OPEN_NO_INDEX_FILES);
	}
	if (box == NULL) {
		i_fatal("Can't open delivery mail as raw: %s",
			mail_storage_get_last_error(raw_ns->storage, &error));
	}
	if (mailbox_sync(box, 0, 0, NULL) < 0) {
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
			destaddr = strchr(user, '@') != NULL ? user :
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
		if (storage == NULL) {
			/* This shouldn't happen */
			i_error("BUG: Saving failed for unknown storage");
			return EX_TEMPFAIL;
		}

		errstr = mail_storage_get_last_error(storage, &error);

		if (stderr_rejection) {
			/* write to stderr also for tempfails so that MTA
			   can log the reason if it wants to. */
			fprintf(stderr, "%s\n", errstr);
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
			    str_sanitize(errstr, 512));

		if (stderr_rejection)
			return EX_NOPERM;
		ret = mail_send_rejection(mail, user, errstr);
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
	duplicate_deinit();

	mail_storage_service_deinit_user();
	master_service_deinit(&service);
        return EX_OK;
}
