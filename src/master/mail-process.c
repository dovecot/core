/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "fd-close-on-exec.h"
#include "env-util.h"
#include "str.h"
#include "network.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "var-expand.h"
#include "mail-process.h"
#include "login-process.h"
#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/stat.h>

static unsigned int mail_process_count = 0;

static int validate_uid_gid(struct settings *set, uid_t uid, gid_t gid,
			    const char *user)
{
	if (uid == 0) {
		i_error("Logins with UID 0 not permitted (user %s)", user);
		return FALSE;
	}

	if (set->login_uid == uid && master_uid != uid) {
		i_error("Can't log in using login processes UID %s (user %s) "
			"(see login_user in config file).",
			dec2str(uid), user);
	}

	if (uid < (uid_t)set->first_valid_uid ||
	    (set->last_valid_uid != 0 && uid > (uid_t)set->last_valid_uid)) {
		i_error("Logins with UID %s (user %s) not permitted "
			"(modify first_valid_uid in config file)",
			dec2str(uid), user);
		return FALSE;
	}

	if (gid < (gid_t)set->first_valid_gid ||
	    (set->last_valid_gid != 0 && gid > (gid_t)set->last_valid_gid)) {
		i_error("Logins for users with primary group ID %s (user %s) "
			"not permitted (see first_valid_gid in config file).",
			dec2str(gid), user);
		return FALSE;
	}

	return TRUE;
}

static int validate_chroot(struct settings *set, const char *dir)
{
	const char *const *chroot_dirs;

	if (*dir == '\0')
		return FALSE;

	if (set->valid_chroot_dirs == NULL)
		return FALSE;

	chroot_dirs = t_strsplit(set->valid_chroot_dirs, ":");
	while (*chroot_dirs != NULL) {
		if (**chroot_dirs != '\0' &&
		    strncmp(dir, *chroot_dirs, strlen(*chroot_dirs)) == 0)
			return TRUE;
		chroot_dirs++;
	}

	return FALSE;
}

static const char *expand_mail_env(const char *env, const char *user,
				   const char *home)
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
		str_append(str, home);
		env++;
	}

	/* expand %vars */
        var_expand(str, env, user, home);
	return str_c(str);
}

static void env_put_namespace(struct namespace_settings *ns,
			      const char *default_location,
			      const char *user, const char *home)
{
	const char *location;
	unsigned int i;
	string_t *str;

	if (default_location == NULL)
		default_location = "";

	for (i = 1; ns != NULL; i++, ns = ns->next) {
		t_push();

		location = ns->location != NULL ? ns->location :
			default_location;
		location = expand_mail_env(location, user, home);
		env_put(t_strdup_printf("NAMESPACE_%u=%s", i, location));

		if (ns->separator != NULL) {
			env_put(t_strdup_printf("NAMESPACE_%u_SEP=%s",
						i, ns->separator));
		}
		if (ns->type != NULL) {
			env_put(t_strdup_printf("NAMESPACE_%u_TYPE=%s",
						i, ns->type));
		}
		if (ns->prefix != NULL) {
			/* expand variables, eg. ~%u/ can be useful */
			str = t_str_new(256);
			str_printfa(str, "NAMESPACE_%u_PREFIX=", i);
			var_expand(str, ns->prefix, user, home);
			env_put(str_c(str));
		}
		if (ns->inbox)
			env_put(t_strdup_printf("NAMESPACE_%u_INBOX=1", i));
		if (ns->hidden)
			env_put(t_strdup_printf("NAMESPACE_%u_HIDDEN=1", i));
		t_pop();
	}
}

int create_mail_process(struct login_group *group, int socket,
			struct ip_addr *ip,
			struct auth_master_reply *reply, const char *data)
{
	const char *argv[4];
	struct settings *set = group->set;
	const char *addr, *mail, *user, *chroot_dir, *home_dir, *full_home_dir;
	const char *executable, *p, *prefix;
	char title[1024];
	pid_t pid;
	int i, err, ret, log_fd;

	// FIXME: per-group
	if (mail_process_count == set->max_mail_processes) {
		i_error("Maximum number of mail processes exceeded");
		return FALSE;
	}

	if (!validate_uid_gid(set, reply->uid, reply->gid,
			      data + reply->virtual_user_idx))
		return FALSE;

	home_dir = data + reply->home_idx;
	chroot_dir = data + reply->chroot_idx;

	if (*chroot_dir == '\0' && set->mail_chroot != NULL)
		chroot_dir = set->mail_chroot;

	if (*chroot_dir != '\0' && !validate_chroot(set, chroot_dir)) {
		i_error("Invalid chroot directory: %s", chroot_dir);
		return FALSE;
	}

	prefix = t_strdup_printf("%s(%s): ", process_names[group->process_type],
				 data + reply->virtual_user_idx);
	log_fd = log_create_pipe(prefix);

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		(void)close(log_fd);
		return FALSE;
	}

	if (pid != 0) {
		/* master */
		mail_process_count++;
		PID_ADD_PROCESS_TYPE(pid, group->process_type);
		(void)close(log_fd);
		return TRUE;
	}

	child_process_init_env();

	/* move the client socket into stdin and stdout fds */
	fd_close_on_exec(socket, FALSE);
	if (dup2(socket, 0) < 0)
		i_fatal("mail: dup2(stdin) failed: %m");
	if (dup2(socket, 1) < 0)
		i_fatal("mail: dup2(stdout) failed: %m");
	if (dup2(log_fd, 2) < 0)
		i_fatal("mail: dup2(stderr) failed: %m");

	if (close(socket) < 0)
		i_error("mail: close(mail client) failed: %m");

	/* setup environment - set the most important environment first
	   (paranoia about filling up environment without noticing) */
	restrict_access_set_env(data + reply->system_user_idx,
				reply->uid, reply->gid, chroot_dir,
				set->first_valid_gid, set->last_valid_gid);

	restrict_process_size(group->set->mail_process_size, (unsigned int)-1);

	if (*home_dir == '\0')
		ret = -1;
	else {
		full_home_dir = *chroot_dir == '\0' ? home_dir :
			t_strconcat(chroot_dir, "/", home_dir, NULL);
		/* NOTE: if home directory is NFS-mounted, we might not
		   have access to it as root. Change the effective UID
		   temporarily to make it work. */
		if (reply->uid != master_uid && seteuid(reply->uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(reply->uid));
		ret = chdir(full_home_dir);
		if (reply->uid != master_uid && seteuid(master_uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(master_uid));

		/* If user's home directory doesn't exist and we're not
		   trying to chroot anywhere, fallback to /tmp as the mails
		   could be stored elsewhere. */
		if (ret < 0 && (errno != ENOENT || *chroot_dir != '\0')) {
			i_fatal("chdir(%s) failed with uid %s: %m",
				full_home_dir, dec2str(reply->uid));
		}
	}
	if (ret < 0) {
		/* We still have to change to some directory where we have
		   rx-access. /tmp should exist everywhere. */
		if (chdir("/tmp") < 0)
			i_fatal("chdir(/tmp) failed: %m");
	}

	env_put("LOGGED_IN=1");
	env_put(t_strconcat("HOME=", home_dir, NULL));
	env_put(t_strconcat("MAIL_CACHE_FIELDS=",
			    set->mail_cache_fields, NULL));
	env_put(t_strconcat("MAIL_NEVER_CACHE_FIELDS=",
			    set->mail_never_cache_fields, NULL));
	env_put(t_strdup_printf("MAILBOX_CHECK_INTERVAL=%u",
				set->mailbox_check_interval));
	env_put(t_strdup_printf("MAILBOX_IDLE_CHECK_INTERVAL=%u",
				set->mailbox_idle_check_interval));
	env_put(t_strconcat("CLIENT_WORKAROUNDS=",
			    set->client_workarounds, NULL));
	env_put(t_strdup_printf("MAIL_MAX_KEYWORD_LENGTH=%u",
				set->mail_max_keyword_length));
	env_put(t_strdup_printf("IMAP_MAX_LINE_LENGTH=%u",
				set->imap_max_line_length));
	env_put(t_strconcat("IMAP_CAPABILITY=",
			    set->imap_capability, NULL));

	if (set->mail_save_crlf)
		env_put("MAIL_SAVE_CRLF=1");
	if (set->mail_read_mmaped)
		env_put("MAIL_READ_MMAPED=1");
	if (set->mmap_disable)
		env_put("MMAP_DISABLE=1");
	if (set->mmap_no_write)
		env_put("MMAP_NO_WRITE=1");
	if (set->fcntl_locks_disable)
		env_put("FCNTL_LOCKS_DISABLE=1");
	if (set->maildir_copy_with_hardlinks)
		env_put("MAILDIR_COPY_WITH_HARDLINKS=1");
	if (set->maildir_check_content_changes)
		env_put("MAILDIR_CHECK_CONTENT_CHANGES=1");
	if (set->mail_full_filesystem_access)
		env_put("FULL_FILESYSTEM_ACCESS=1");
	if (set->pop3_mails_keep_recent)
		env_put("POP3_MAILS_KEEP_RECENT=1");
	(void)umask(set->umask);

	env_put(t_strconcat("MBOX_LOCKS=", set->mbox_locks, NULL));
	env_put(t_strdup_printf("MBOX_LOCK_TIMEOUT=%u",
				set->mbox_lock_timeout));
	env_put(t_strdup_printf("MBOX_DOTLOCK_CHANGE_TIMEOUT=%u",
				set->mbox_dotlock_change_timeout));
	if (set->mbox_read_dotlock)
		env_put("MBOX_READ_DOTLOCK=1");

	if (group->set->mail_use_modules &&
	    group->set->mail_modules != NULL &&
	    *group->set->mail_modules != '\0') {
		env_put(t_strconcat("MODULE_DIR=",
				    group->set->mail_modules, NULL));
	}

	/* user given environment - may be malicious. virtual_user comes from
	   auth process, but don't trust that too much either. Some auth
	   mechanism might allow leaving extra data there. */
	mail = data + reply->mail_idx;
	user = data + reply->virtual_user_idx;
	if (*mail == '\0' && set->default_mail_env != NULL)
		mail = expand_mail_env(set->default_mail_env, user, home_dir);

	if (set->server->namespaces != NULL) {
		env_put_namespace(set->server->namespaces,
				  mail, user, home_dir);
	}

	env_put(t_strconcat("MAIL=", mail, NULL));
	env_put(t_strconcat("USER=", data + reply->virtual_user_idx, NULL));

	addr = net_ip2addr(ip);
	env_put(t_strconcat("IP=", addr, NULL));

	if (!set->verbose_proctitle)
		title[0] = '\0';
	else {
		if (addr == NULL)
			addr = "??";

		i_snprintf(title, sizeof(title), "[%s %s]",
			   data + reply->virtual_user_idx, addr);
	}

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	if (set->mail_drop_priv_before_exec)
		restrict_access_by_env(TRUE);

	/* very simple argument splitting. */
	i = 0;
	argv[i++] = executable = t_strcut(group->set->mail_executable, ' ');
	argv[i] = strchr(group->set->mail_executable, ' ');
	if (argv[i] != NULL) {
		argv[i]++;
		i++;
	}
	if (title[0] != '\0')
		argv[i++] = title;
	argv[i] = NULL;

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	execv(executable, (char **) argv);
	err = errno;

	for (i = 0; i < 3; i++)
		(void)close(i);

	errno = err;
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
		       group->set->mail_executable);

	/* not reached */
	return FALSE;
}

void mail_process_destroyed(pid_t pid __attr_unused__)
{
	mail_process_count--;
}
