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
		i_error("Logins with login process UID %s (user %s) "
			"not permitted (see login_user in config file).",
			dec2str(uid), user);
	}

	if (uid < (uid_t)set->first_valid_uid ||
	    (set->last_valid_uid != 0 && uid > (uid_t)set->last_valid_uid)) {
		i_error("Logins with UID %s (user %s) not permitted "
			"(see first_valid_uid in config file)",
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

static const struct var_expand_table *
get_var_expand_table(const char *protocol,
		     const char *user, const char *home,
		     const char *local_ip, const char *remote_ip, pid_t pid)
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
		{ '\0', NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = user;
	tab[1].value = t_strcut(user, '@');
	tab[2].value = strchr(user, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = t_str_ucase(protocol);
	tab[4].value = home;
	tab[5].value = local_ip;
	tab[6].value = remote_ip;
	tab[7].value = dec2str(pid);

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

static void
env_put_namespace(struct namespace_settings *ns, const char *default_location,
		  const struct var_expand_table *table)
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
		location = expand_mail_env(location, table);
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
			var_expand(str, ns->prefix, table);
			env_put(str_c(str));
		}
		if (ns->inbox)
			env_put(t_strdup_printf("NAMESPACE_%u_INBOX=1", i));
		if (ns->hidden)
			env_put(t_strdup_printf("NAMESPACE_%u_HIDDEN=1", i));
		t_pop();
	}
}

static void
mail_process_set_environment(struct settings *set, const char *mail,
			     const struct var_expand_table *var_expand_table)
{
	env_put(t_strconcat("MAIL_CACHE_FIELDS=",
			    set->mail_cache_fields, NULL));
	env_put(t_strconcat("MAIL_NEVER_CACHE_FIELDS=",
			    set->mail_never_cache_fields, NULL));
	env_put(t_strdup_printf("MAILBOX_IDLE_CHECK_INTERVAL=%u",
				set->mailbox_idle_check_interval));
	env_put(t_strdup_printf("MAIL_MAX_KEYWORD_LENGTH=%u",
				set->mail_max_keyword_length));
	env_put(t_strdup_printf("IMAP_MAX_LINE_LENGTH=%u",
				set->imap_max_line_length));
	env_put(t_strconcat("IMAP_CAPABILITY=",
			    set->imap_capability, NULL));
	env_put(t_strconcat("IMAP_CLIENT_WORKAROUNDS=",
			    set->imap_client_workarounds, NULL));
	env_put(t_strconcat("POP3_UIDL_FORMAT=",
			    set->pop3_uidl_format, NULL));
	env_put(t_strconcat("POP3_CLIENT_WORKAROUNDS=",
			    set->pop3_client_workarounds, NULL));

	if (set->mail_save_crlf)
		env_put("MAIL_SAVE_CRLF=1");
	if (set->mail_read_mmaped)
		env_put("MAIL_READ_MMAPED=1");
	if (set->mmap_disable)
		env_put("MMAP_DISABLE=1");
	if (set->mmap_no_write)
		env_put("MMAP_NO_WRITE=1");
	if (set->maildir_stat_dirs)
		env_put("MAILDIR_STAT_DIRS=1");
	if (set->maildir_copy_with_hardlinks)
		env_put("MAILDIR_COPY_WITH_HARDLINKS=1");
	if (set->mail_full_filesystem_access)
		env_put("FULL_FILESYSTEM_ACCESS=1");
	if (set->pop3_no_flag_updates)
		env_put("POP3_NO_FLAG_UPDATES=1");
	if (set->pop3_enable_last)
		env_put("POP3_ENABLE_LAST=1");
	if (set->mbox_dirty_syncs)
		env_put("MBOX_DIRTY_SYNCS=1");
	if (set->mbox_very_dirty_syncs)
		env_put("MBOX_VERY_DIRTY_SYNCS=1");
	if (set->mbox_lazy_writes)
		env_put("MBOX_LAZY_WRITES=1");
	(void)umask(set->umask);

	env_put(t_strconcat("LOCK_METHOD=", set->lock_method, NULL));
	env_put(t_strconcat("MBOX_READ_LOCKS=", set->mbox_read_locks, NULL));
	env_put(t_strconcat("MBOX_WRITE_LOCKS=", set->mbox_write_locks, NULL));
	env_put(t_strdup_printf("MBOX_LOCK_TIMEOUT=%u",
				set->mbox_lock_timeout));
	env_put(t_strdup_printf("MBOX_DOTLOCK_CHANGE_TIMEOUT=%u",
				set->mbox_dotlock_change_timeout));

	if (set->mail_use_modules &&
	    set->mail_modules != NULL && *set->mail_modules != '\0') {
		env_put(t_strconcat("MODULE_DIR=",
				    set->mail_modules, NULL));
	}

	/* user given environment - may be malicious. virtual_user comes from
	   auth process, but don't trust that too much either. Some auth
	   mechanism might allow leaving extra data there. */
	if ((mail == NULL || *mail == '\0') && set->default_mail_env != NULL)
		mail = expand_mail_env(set->default_mail_env, var_expand_table);
	env_put(t_strconcat("MAIL=", mail, NULL));

	if (set->server->namespaces != NULL) {
		env_put_namespace(set->server->namespaces,
				  mail, var_expand_table);
	}
}

void mail_process_exec(const char *protocol, const char *section)
{
	struct server_settings *server = settings_root;
	const struct var_expand_table *var_expand_table;
	struct settings *set;

	if (section != NULL) {
		for (; server != NULL; server = server->next) {
			if (strcmp(server->name, section) == 0)
				break;
		}
		if (server == NULL)
			i_fatal("Section not found: '%s'", section);
	}

	if (strcmp(protocol, "imap") == 0)
		set = server->imap;
	else if (strcmp(protocol, "pop3") == 0)
		set = server->pop3;
	else
		i_fatal("Unknown protocol: '%s'", protocol);

	var_expand_table =
		get_var_expand_table(protocol, getenv("USER"), getenv("HOME"),
				     getenv("TCPLOCALIP"),
				     getenv("TCPREMOTEIP"), getpid());

	mail_process_set_environment(set, getenv("MAIL"), var_expand_table);
        client_process_exec(set->mail_executable, "");

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
		       set->mail_executable);
}

int create_mail_process(struct login_group *group, int socket,
			const struct ip_addr *local_ip,
			const struct ip_addr *remote_ip,
			const char *user, const char *const *args)
{
	struct settings *set = group->set;
	const struct var_expand_table *var_expand_table;
	const char *addr, *mail, *chroot_dir, *home_dir, *full_home_dir;
	const char *system_user;
	char title[1024];
	struct log_io *log;
	string_t *str;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	int i, err, ret, log_fd;

	// FIXME: per-group
	if (mail_process_count == set->max_mail_processes) {
		i_error("Maximum number of mail processes exceeded");
		return FALSE;
	}

	mail = home_dir = chroot_dir = system_user = "";
	uid = gid = 0;
	for (; *args != NULL; args++) {
		if (strncmp(*args, "home=", 5) == 0)
			home_dir = *args + 5;
		else if (strncmp(*args, "mail=", 5) == 0)
			mail = *args + 5;
		else if (strncmp(*args, "chroot=", 7) == 0)
			chroot_dir = *args + 7;
		else if (strncmp(*args, "system_user=", 12) == 0)
			system_user = *args + 12;
		else if (strncmp(*args, "uid=", 4) == 0)
			uid = (uid_t)strtoul(*args + 4, NULL, 10);
		else if (strncmp(*args, "gid=", 4) == 0)
			gid = (gid_t)strtoul(*args + 4, NULL, 10);
	}

	if (!validate_uid_gid(set, uid, gid, user))
		return FALSE;

	if (*chroot_dir == '\0' && set->mail_chroot != NULL)
		chroot_dir = set->mail_chroot;

	if (*chroot_dir != '\0' && !validate_chroot(set, chroot_dir)) {
		i_error("Invalid chroot directory '%s' (user %s) "
			"(see valid_chroot_dirs in config file)",
			chroot_dir, user);
		return FALSE;
	}

	log_fd = log_create_pipe(&log);

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		(void)close(log_fd);
		return FALSE;
	}

	var_expand_table =
		get_var_expand_table(process_names[group->process_type],
				     user, home_dir,
				     net_ip2addr(local_ip),
				     net_ip2addr(remote_ip),
				     pid != 0 ? pid : getpid());
	str = t_str_new(128);

	if (pid != 0) {
		/* master */
		var_expand(str, set->mail_log_prefix, var_expand_table);
		log_set_prefix(log, str_c(str));

		mail_process_count++;
		PID_ADD_PROCESS_TYPE(pid, group->process_type);
		(void)close(log_fd);
		return TRUE;
	}

	str_append(str, "master-");
	var_expand(str, set->mail_log_prefix, var_expand_table);
	log_set_prefix(log, str_c(str));

	child_process_init_env();

	/* move the client socket into stdin and stdout fds, log to stderr */
	if (dup2(socket, 0) < 0)
		i_fatal("dup2(stdin) failed: %m");
	if (dup2(socket, 1) < 0)
		i_fatal("dup2(stdout) failed: %m");
	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");

	for (i = 0; i < 3; i++)
		fd_close_on_exec(i, FALSE);

	/* setup environment - set the most important environment first
	   (paranoia about filling up environment without noticing) */
	restrict_access_set_env(system_user, uid, gid, chroot_dir,
				set->first_valid_gid, set->last_valid_gid,
				set->mail_extra_groups);

	restrict_process_size(set->mail_process_size, (unsigned int)-1);

	if (*home_dir == '\0')
		ret = -1;
	else {
		full_home_dir = *chroot_dir == '\0' ? home_dir :
			t_strconcat(chroot_dir, "/", home_dir, NULL);
		/* NOTE: if home directory is NFS-mounted, we might not
		   have access to it as root. Change the effective UID
		   temporarily to make it work. */
		if (uid != master_uid && seteuid(uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(uid));
		ret = chdir(full_home_dir);
		if (uid != master_uid && seteuid(master_uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(master_uid));

		/* If user's home directory doesn't exist and we're not
		   trying to chroot anywhere, fallback to /tmp as the mails
		   could be stored elsewhere. */
		if (ret < 0 && (errno != ENOENT || *chroot_dir != '\0')) {
			i_fatal("chdir(%s) failed with uid %s: %m",
				full_home_dir, dec2str(uid));
		}
	}
	if (ret < 0) {
		/* We still have to change to some directory where we have
		   rx-access. /tmp should exist everywhere. */
		if (chdir("/tmp") < 0)
			i_fatal("chdir(/tmp) failed: %m");
	}

        mail_process_set_environment(set, mail, var_expand_table);

	env_put("LOGGED_IN=1");
	env_put(t_strconcat("HOME=", home_dir, NULL));
	env_put(t_strconcat("USER=", user, NULL));

	addr = net_ip2addr(remote_ip);
	env_put(t_strconcat("IP=", addr, NULL));

	if (!set->verbose_proctitle)
		title[0] = '\0';
	else {
		if (addr == NULL)
			addr = "??";

		i_snprintf(title, sizeof(title), "[%s %s]", user, addr);
	}

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	if (set->mail_drop_priv_before_exec)
		restrict_access_by_env(TRUE);

	client_process_exec(set->mail_executable, title);
	err = errno;

	for (i = 0; i < 3; i++)
		(void)close(i);

	errno = err;
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
		       set->mail_executable);

	/* not reached */
	return FALSE;
}

void mail_process_destroyed(pid_t pid __attr_unused__)
{
	mail_process_count--;
}
