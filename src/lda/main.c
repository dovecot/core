/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "env-util.h"
#include "fd-set-nonblock.h"
#include "close-keep-errno.h"
#include "istream.h"
#include "istream-seekable.h"
#include "safe-mkstemp.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "imap-utf7.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "raw-storage.h"
#include "mail-deliver.h"
#include "mail-send.h"
#include "duplicate.h"
#include "mbox-from.h"
#include "lda-settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sysexits.h>

#define DEFAULT_ENVELOPE_SENDER "MAILER-DAEMON"

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
//#define MAIL_MAX_MEMORY_BUFFER (1024*128)
#define MAIL_MAX_MEMORY_BUFFER 10

static const char *wanted_headers[] = {
	"From", "To", "Message-ID", "Subject", "Return-Path",
	NULL
};

static const char *escape_local_part(const char *local_part)
{
	const char *p;

	/* if local_part isn't dot-atom-text, we need to return quoted-string
	   dot-atom-text = 1*atext *("." 1*atext) */
	for (p = local_part; *p != '\0'; p++) {
		if (!IS_ATEXT(*p) && *p != '.')
			break;
	}
	if (*p != '\0' || *local_part == '.' ||
	    (p != local_part && p[-1] == '.'))
		local_part = t_strdup_printf("\"%s\"", str_escape(local_part));
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

static int deliver_create_dir(struct mail_user *user, const char *dir)
{
	struct mail_namespace *ns;
	const char *origin;
	mode_t mode;
	gid_t gid;

	ns = mail_namespace_find_inbox(user->namespaces);
	if (ns == NULL)
		ns = user->namespaces;

	mailbox_list_get_dir_permissions(ns->list, NULL, &mode, &gid, &origin);
	if (mkdir_parents_chgrp(dir, mode, gid, origin) == 0) {
		return 0;
	} else if (errno == EACCES) {
		i_error("%s", eacces_error_get_creating("mkdir_parents_chown",
							dir));
		return -1;
	} else {
		i_error("mkdir_parents_chown(%s, gid=%s) failed: %m",
			dir, dec2str(gid));
		return -1;
	}
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	struct mail_deliver_context *ctx = context;
	const char *dir, *p;
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, mail_user_get_temp_prefix(ctx->dest_user));
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1 && errno == ENOENT) {
		dir = str_c(path);
		p = strrchr(dir, '/');
		if (p != NULL) {
			dir = t_strdup_until(dir, p);
			if (deliver_create_dir(ctx->dest_user, dir) < 0)
				return -1;
			fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
		}
	}
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		close_keep_errno(fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static struct istream *
create_raw_stream(struct mail_deliver_context *ctx,
		  int fd, time_t *mtime_r)
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

	if (sender != NULL && ctx->src_envelope_sender == NULL) {
		/* use the envelope sender from From_-line, but only if it
		   hasn't been specified with -f already. */
		ctx->src_envelope_sender = p_strdup(ctx->pool, sender);
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
					 seekable_fd_callback, ctx);
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
"Usage: dovecot-lda [-c <config file>] [-a <address>] [-d <username>] [-p <path>]\n"
"                   [-f <envelope sender>] [-m <mailbox>] [-e] [-k]\n");
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		NULL
	};
	struct mail_deliver_context ctx;
	enum mail_storage_service_flags service_flags = 0;
	const char *user, *errstr, *path;
	struct mail_storage_service_input service_input;
	struct mail_user *raw_mail_user;
	struct mail_namespace *raw_ns;
	struct mail_namespace_settings raw_ns_set;
	struct mail_storage *storage;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct istream *input;
	struct mailbox_transaction_context *t;
	struct mailbox_header_lookup_ctx *headers_ctx;
	char cwd[PATH_MAX];
	void **sets;
	uid_t process_euid;
	bool stderr_rejection = FALSE;
	time_t mtime;
	int ret, c;
	string_t *str;
	enum mail_error error;

	if (getuid() != geteuid() && geteuid() == 0) {
		/* running setuid - don't allow this if the binary is
		   executable by anyone */
		struct stat st;

		if (stat(argv[0], &st) < 0) {
			fprintf(stderr, "stat(%s) failed: %s\n",
				argv[0], strerror(errno));
			return EX_TEMPFAIL;
		} else if ((st.st_mode & 1) != 0) {
			fprintf(stderr, "%s must not be both world-executable "
				"and setuid-root. This allows root exploits. "
				"See http://wiki.dovecot.org/LDA#multipleuids\n",
				argv[0]);
			return EX_TEMPFAIL;
		}
	}

	i_set_failure_exit_callback(failure_exit_callback);

	master_service = master_service_init("lda",
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR,
		&argc, &argv, "a:d:p:ekm:nsf:");

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool_alloconly_create("mail deliver context", 256);
	ctx.dest_mailbox_name = "INBOX";
	path = NULL;

	user = getenv("USER");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			/* destination address */
			ctx.dest_addr = optarg;
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
			if (*optarg != '\0') T_BEGIN {
				str = t_str_new(256);
				if (imap_utf8_to_utf7(optarg, str) < 0) {
					i_fatal("Mailbox name not UTF-8: %s",
						optarg);
				}
				ctx.dest_mailbox_name =
					p_strdup(ctx.pool, str_c(str));
			} T_END;
			break;
		case 'f':
			/* envelope sender address */
			ctx.src_envelope_sender =
				p_strdup(ctx.pool, address_sanitize(optarg));
			break;
		default:
			print_help();
			return EX_USAGE;
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
	master_service_init_finish(master_service);

	memset(&service_input, 0, sizeof(service_input));
	service_input.module = "lda";
	service_input.service = "lda";
	service_input.username = user;

	service_flags |= MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;
	ctx.dest_user = mail_storage_service_init_user(master_service,
						       &service_input,
						       set_roots,
						       service_flags);
#ifdef SIGXFSZ
        lib_signals_ignore(SIGXFSZ, TRUE);
#endif
	ctx.set = mail_storage_service_get_settings(master_service);
        duplicate_init(mail_user_set_get_storage_set(ctx.dest_user->set));

	/* create a separate mail user for the internal namespace */
	if (master_service_set(master_service,
			       "mail_full_filesystem_access=yes") < 0)
		i_unreached();
	sets = master_service_settings_get_others(master_service);
	raw_mail_user = mail_user_alloc(user, sets[0]);
	mail_user_set_home(raw_mail_user, "/");
	if (mail_user_init(raw_mail_user, &errstr) < 0)
		i_fatal("Raw user initialization failed: %s", errstr);

	memset(&raw_ns_set, 0, sizeof(raw_ns_set));
	raw_ns_set.location = "/tmp";

	raw_ns = mail_namespaces_init_empty(raw_mail_user);
	raw_ns->flags |= NAMESPACE_FLAG_NOQUOTA | NAMESPACE_FLAG_NOACL;
	raw_ns->set = &raw_ns_set;
	if (mail_storage_create(raw_ns, "raw", 0, &errstr) < 0)
		i_fatal("Couldn't create internal raw storage: %s", errstr);
	if (path == NULL) {
		input = create_raw_stream(&ctx, 0, &mtime);
		box = mailbox_alloc(raw_ns->list, "Dovecot Delivery Mail",
				    input, MAILBOX_FLAG_NO_INDEX_FILES);
		i_stream_unref(&input);
	} else {
		mtime = (time_t)-1;
		box = mailbox_alloc(raw_ns->list, path, NULL,
				    MAILBOX_FLAG_NO_INDEX_FILES);
	}
	if (mailbox_open(box) < 0) {
		i_fatal("Can't open delivery mail as raw: %s",
			mail_storage_get_last_error(box->storage, &error));
	}
	if (mailbox_sync(box, 0, 0, NULL) < 0) {
		i_fatal("Can't sync delivery mail: %s",
			mail_storage_get_last_error(box->storage, &error));
	}
	raw_box = (struct raw_mailbox *)box;
	raw_box->envelope_sender = ctx.src_envelope_sender != NULL ?
		ctx.src_envelope_sender : DEFAULT_ENVELOPE_SENDER;
	raw_box->mtime = mtime;

	t = mailbox_transaction_begin(box, 0);
	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	ctx.src_mail = mail_alloc(t, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(ctx.src_mail, 1);

	if (ctx.dest_addr == NULL) {
		ctx.dest_addr = mail_deliver_get_address(&ctx, "Envelope-To");
		if (ctx.dest_addr == NULL) {
			ctx.dest_addr = strchr(user, '@') != NULL ? user :
				t_strconcat(user, "@", ctx.set->hostname, NULL);
		}
	}

	if (mail_deliver(&ctx, &storage) < 0) {
		if (storage == NULL) {
			/* This shouldn't happen */
			i_error("BUG: Saving failed to unknown storage");
			return EX_TEMPFAIL;
		}

		errstr = mail_storage_get_last_error(storage, &error);

		if (stderr_rejection) {
			/* write to stderr also for tempfails so that MTA
			   can log the reason if it wants to. */
			fprintf(stderr, "%s\n", errstr);
		}

		if (error != MAIL_ERROR_NOSPACE ||
		    ctx.set->quota_full_tempfail) {
			/* Saving to INBOX should always work unless
			   we're over quota. If it didn't, it's probably a
			   configuration problem. */
			return EX_TEMPFAIL;
		}

		/* we'll have to reply with permanent failure */
		mail_deliver_log(&ctx, "rejected: %s",
				 str_sanitize(errstr, 512));

		if (stderr_rejection)
			return EX_NOPERM;
		ret = mail_send_rejection(&ctx, user, errstr);
		if (ret != 0)
			return ret < 0 ? EX_TEMPFAIL : ret;
		/* ok, rejection sent */
	}

	mail_free(&ctx.src_mail);
	mailbox_transaction_rollback(&t);
	mailbox_close(&box);

	mail_user_unref(&ctx.dest_user);
	mail_user_unref(&raw_mail_user);
	duplicate_deinit();
	pool_unref(&ctx.pool);

	mail_storage_service_deinit_user();
	master_service_deinit(&master_service);
        return EX_OK;
}
