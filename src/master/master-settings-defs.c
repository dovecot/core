/* kludgy: this file is included from master-settings.c and from deliver */

#define DEF(type, name) \
	{ type, #name, offsetof(struct settings, name) }

static struct setting_def setting_defs[] = {
	/* common */
	DEF(SET_STR, base_dir),
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),

	/* general */
	DEF(SET_STR, protocols),
	DEF(SET_STR, listen),
	DEF(SET_STR, ssl_listen),

	DEF(SET_BOOL, ssl_disable),
	DEF(SET_STR, ssl_ca_file),
	DEF(SET_STR, ssl_cert_file),
	DEF(SET_STR, ssl_key_file),
	DEF(SET_STR, ssl_key_password),
	DEF(SET_INT, ssl_parameters_regenerate),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_BOOL, ssl_verify_client_cert),
	DEF(SET_BOOL, disable_plaintext_auth),
	DEF(SET_BOOL, verbose_ssl),
	DEF(SET_BOOL, shutdown_clients),
	DEF(SET_BOOL, nfs_check),
	DEF(SET_BOOL, version_ignore),

	/* login */
	DEF(SET_STR, login_dir),
	DEF(SET_STR, login_executable),
	DEF(SET_STR, login_user),
	DEF(SET_STR, login_greeting),
	DEF(SET_STR, login_log_format_elements),
	DEF(SET_STR, login_log_format),

	DEF(SET_BOOL, login_process_per_connection),
	DEF(SET_BOOL, login_chroot),
	DEF(SET_BOOL, login_greeting_capability),

	DEF(SET_INT, login_process_size),
	DEF(SET_INT, login_processes_count),
	DEF(SET_INT, login_max_processes_count),
	DEF(SET_INT, login_max_connections),

	/* mail */
	DEF(SET_STR, valid_chroot_dirs),
	DEF(SET_STR, mail_chroot),
	DEF(SET_INT, max_mail_processes),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_INT, first_valid_uid),
	DEF(SET_INT, last_valid_uid),
	DEF(SET_INT, first_valid_gid),
	DEF(SET_INT, last_valid_gid),
	DEF(SET_STR, mail_extra_groups),

	DEF(SET_STR, default_mail_env),
	DEF(SET_STR, mail_location),
	DEF(SET_STR, mail_cache_fields),
	DEF(SET_STR, mail_never_cache_fields),
	DEF(SET_INT, mail_cache_min_mail_count),
	DEF(SET_INT, mailbox_idle_check_interval),
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, mail_full_filesystem_access),
	DEF(SET_INT, mail_max_keyword_length),
	DEF(SET_BOOL, mail_save_crlf),
	DEF(SET_BOOL, mmap_disable),
	DEF(SET_BOOL, mmap_no_write),
	DEF(SET_BOOL, dotlock_use_excl),
	DEF(SET_BOOL, fsync_disable),
	DEF(SET_STR, lock_method),
	DEF(SET_BOOL, maildir_stat_dirs),
	DEF(SET_BOOL, maildir_copy_with_hardlinks),
	DEF(SET_BOOL, maildir_copy_preserve_filename),
	DEF(SET_STR, mbox_read_locks),
	DEF(SET_STR, mbox_write_locks),
	DEF(SET_INT, mbox_lock_timeout),
	DEF(SET_INT, mbox_dotlock_change_timeout),
	DEF(SET_INT, mbox_min_index_size),
	DEF(SET_BOOL, mbox_dirty_syncs),
	DEF(SET_BOOL, mbox_very_dirty_syncs),
	DEF(SET_BOOL, mbox_lazy_writes),
	DEF(SET_INT, dbox_rotate_size),
	DEF(SET_INT, dbox_rotate_min_size),
	DEF(SET_INT, dbox_rotate_days),
	DEF(SET_INT, umask),
	DEF(SET_BOOL, mail_drop_priv_before_exec),

	DEF(SET_STR, mail_executable),
	DEF(SET_INT, mail_process_size),
	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),
	DEF(SET_STR, mail_log_prefix),
	DEF(SET_STR, mail_log_max_lines_per_sec),

	/* imap */
	DEF(SET_INT, imap_max_line_length),
	DEF(SET_STR, imap_capability),
	DEF(SET_STR, imap_client_workarounds),

	/* pop3 */
	DEF(SET_BOOL, pop3_no_flag_updates),
	DEF(SET_BOOL, pop3_enable_last),
	DEF(SET_BOOL, pop3_reuse_xuidl),
	DEF(SET_BOOL, pop3_lock_session),
	DEF(SET_STR, pop3_uidl_format),
	DEF(SET_STR, pop3_client_workarounds),
	DEF(SET_STR, pop3_logout_format),

	{ 0, NULL, 0 }
};
