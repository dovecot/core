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

#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/stat.h>

static unsigned int mail_process_count = 0;

static int validate_uid_gid(uid_t uid, gid_t gid)
{
	if (uid == 0) {
		i_error("mail process isn't allowed for root");
		return FALSE;
	}

	if (uid != 0 && gid == 0) {
		i_error("mail process isn't allowed to be in group 0");
		return FALSE;
	}

	if (uid < (uid_t)set->first_valid_uid ||
	    (set->last_valid_uid != 0 && uid > (uid_t)set->last_valid_uid)) {
		i_error("mail process isn't allowed to use UID %s",
			dec2str(uid));
		return FALSE;
	}

	if (gid < (gid_t)set->first_valid_gid ||
	    (set->last_valid_gid != 0 && gid > (gid_t)set->last_valid_gid)) {
		i_error("mail process isn't allowed to use "
			"GID %s (UID is %s)", dec2str(gid), dec2str(uid));
		return FALSE;
	}

	return TRUE;
}

static int validate_chroot(const char *dir)
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

int create_mail_process(int socket, struct ip_addr *ip,
			const char *executable, unsigned int process_size,
			struct auth_master_reply *reply, const char *data)
{
	static const char *argv[] = { NULL, NULL, NULL };
	const char *host, *mail;
	char title[1024];
	pid_t pid;
	int i, err;

	if (mail_process_count == set->max_mail_processes) {
		i_error("Maximum number of mail processes exceeded");
		return FALSE;
	}

	if (!validate_uid_gid(reply->uid, reply->gid))
		return FALSE;

	if (reply->chroot && !validate_chroot(data + reply->home_idx))
		return FALSE;

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		return FALSE;
	}

	if (pid != 0) {
		/* master */
		mail_process_count++;
		PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_MAIL);
		return TRUE;
	}

	clean_child_process();

	/* move the client socket into stdin and stdout fds */
	fd_close_on_exec(socket, FALSE);
	if (dup2(socket, 0) < 0)
		i_fatal("mail: dup2(stdin) failed: %m");
	if (dup2(socket, 1) < 0)
		i_fatal("mail: dup2(stdout) failed: %m");

	if (close(socket) < 0)
		i_error("mail: close(mail client) failed: %m");

	/* setup environment - set the most important environment first
	   (paranoia about filling up environment without noticing) */
	restrict_access_set_env(data + reply->system_user_idx,
				reply->uid, reply->gid,
				reply->chroot ? data + reply->home_idx : NULL);

	restrict_process_size(process_size, (unsigned int)-1);

	env_put("LOGGED_IN=1");
	env_put(t_strconcat("HOME=", data + reply->home_idx, NULL));
	env_put(t_strconcat("MAIL_CACHE_FIELDS=",
			    set->mail_cache_fields, NULL));
	env_put(t_strconcat("MAIL_NEVER_CACHE_FIELDS=",
			    set->mail_never_cache_fields, NULL));
	env_put(t_strdup_printf("MAILBOX_CHECK_INTERVAL=%u",
				set->mailbox_check_interval));
	env_put(t_strconcat("CLIENT_WORKAROUNDS=",
			    set->client_workarounds, NULL));

	if (set->mail_save_crlf)
		env_put("MAIL_SAVE_CRLF=1");
	if (set->mail_read_mmaped)
		env_put("MAIL_READ_MMAPED=1");
	if (set->maildir_copy_with_hardlinks)
		env_put("MAILDIR_COPY_WITH_HARDLINKS=1");
	if (set->maildir_check_content_changes)
		env_put("MAILDIR_CHECK_CONTENT_CHANGES=1");
	if (set->overwrite_incompatible_index)
		env_put("OVERWRITE_INCOMPATIBLE_INDEX=1");
	if (set->mail_full_filesystem_access)
		env_put("FULL_FILESYSTEM_ACCESS=1");
	if (umask(set->umask) != set->umask)
		i_fatal("Invalid umask: %o", set->umask);

	env_put(t_strconcat("MBOX_LOCKS=", set->mbox_locks, NULL));
	env_put(t_strdup_printf("MBOX_LOCK_TIMEOUT=%u",
				set->mbox_lock_timeout));
	env_put(t_strdup_printf("MBOX_DOTLOCK_CHANGE_TIMEOUT=%u",
				set->mbox_dotlock_change_timeout));
	if (set->mbox_read_dotlock)
		env_put("MBOX_READ_DOTLOCK=1");

	/* user given environment - may be malicious. virtual_user comes from
	   auth process, but don't trust that too much either. Some auth
	   mechanism might allow leaving extra data there. */
	mail = data + reply->mail_idx;
	if (*mail == '\0' && set->default_mail_env != NULL) {
		mail = expand_mail_env(set->default_mail_env,
				       data + reply->virtual_user_idx,
				       data + reply->home_idx);
	}

	env_put(t_strconcat("MAIL=", mail, NULL));
	env_put(t_strconcat("USER=", data + reply->virtual_user_idx, NULL));

	if (set->verbose_proctitle) {
		host = net_ip2host(ip);
		if (host == NULL)
			host = "??";

		i_snprintf(title, sizeof(title), "[%s %s]",
			   data + reply->virtual_user_idx, host);
		argv[1] = title;
	}

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	/* hide the path, it's ugly */
	argv[0] = strrchr(executable, '/');
	if (argv[0] == NULL) argv[0] = executable; else argv[0]++;

	execv(executable, (char **) argv);
	err = errno;

	for (i = 0; i < 3; i++)
		(void)close(i);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);

	/* not reached */
	return FALSE;
}

void mail_process_destroyed(pid_t pid __attr_unused__)
{
	mail_process_count--;
}
