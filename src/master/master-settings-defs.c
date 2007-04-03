/* kludgy: this file is included from master-settings.c and from deliver */

#undef DEF_STR
#undef DEF_INT
#undef DEF_BOOL
#define DEF_STR(name) DEF_STRUCT_STR(name, settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, settings)

static struct setting_def setting_defs[] = {
	/* common */
	DEF_STR(base_dir),
	DEF_STR(log_path),
	DEF_STR(info_log_path),
	DEF_STR(log_timestamp),
	DEF_STR(syslog_facility),

	/* general */
	DEF_STR(protocols),
	DEF_STR(listen),
	DEF_STR(ssl_listen),

	DEF_BOOL(ssl_disable),
	DEF_STR(ssl_ca_file),
	DEF_STR(ssl_cert_file),
	DEF_STR(ssl_key_file),
	DEF_STR(ssl_key_password),
	DEF_INT(ssl_parameters_regenerate),
	DEF_STR(ssl_cipher_list),
	DEF_BOOL(ssl_verify_client_cert),
	DEF_BOOL(disable_plaintext_auth),
	DEF_BOOL(verbose_ssl),
	DEF_BOOL(shutdown_clients),
	DEF_BOOL(nfs_check),
	DEF_BOOL(version_ignore),

	/* login */
	DEF_STR(login_dir),
	DEF_STR(login_executable),
	DEF_STR(login_user),
	DEF_STR(login_greeting),
	DEF_STR(login_log_format_elements),
	DEF_STR(login_log_format),

	DEF_BOOL(login_process_per_connection),
	DEF_BOOL(login_chroot),
	DEF_BOOL(login_greeting_capability),

	DEF_INT(login_process_size),
	DEF_INT(login_processes_count),
	DEF_INT(login_max_processes_count),
	DEF_INT(login_max_connections),

	/* mail */
	DEF_STR(valid_chroot_dirs),
	DEF_STR(mail_chroot),
	DEF_INT(max_mail_processes),
	DEF_BOOL(verbose_proctitle),

	DEF_INT(first_valid_uid),
	DEF_INT(last_valid_uid),
	DEF_INT(first_valid_gid),
	DEF_INT(last_valid_gid),
	DEF_STR(mail_extra_groups),

	DEF_STR(default_mail_env),
	DEF_STR(mail_location),
	DEF_STR(mail_cache_fields),
	DEF_STR(mail_never_cache_fields),
	DEF_INT(mail_cache_min_mail_count),
	DEF_INT(mailbox_idle_check_interval),
	DEF_BOOL(mail_debug),
	DEF_BOOL(mail_full_filesystem_access),
	DEF_INT(mail_max_keyword_length),
	DEF_BOOL(mail_save_crlf),
	DEF_BOOL(mmap_disable),
	DEF_BOOL(mmap_no_write),
	DEF_BOOL(dotlock_use_excl),
	DEF_BOOL(fsync_disable),
	DEF_BOOL(mailbox_list_index_disable),
	DEF_STR(lock_method),
	DEF_BOOL(maildir_stat_dirs),
	DEF_BOOL(maildir_copy_with_hardlinks),
	DEF_BOOL(maildir_copy_preserve_filename),
	DEF_STR(mbox_read_locks),
	DEF_STR(mbox_write_locks),
	DEF_INT(mbox_lock_timeout),
	DEF_INT(mbox_dotlock_change_timeout),
	DEF_INT(mbox_min_index_size),
	DEF_BOOL(mbox_dirty_syncs),
	DEF_BOOL(mbox_very_dirty_syncs),
	DEF_BOOL(mbox_lazy_writes),
	DEF_INT(dbox_rotate_size),
	DEF_INT(dbox_rotate_min_size),
	DEF_INT(dbox_rotate_days),
	DEF_INT(umask),
	DEF_BOOL(mail_drop_priv_before_exec),

	DEF_STR(mail_executable),
	DEF_INT(mail_process_size),
	DEF_STR(mail_plugins),
	DEF_STR(mail_plugin_dir),
	DEF_STR(mail_log_prefix),
	DEF_INT(mail_log_max_lines_per_sec),

	/* imap */
	DEF_INT(imap_max_line_length),
	DEF_STR(imap_capability),
	DEF_STR(imap_client_workarounds),

	/* pop3 */
	DEF_BOOL(pop3_no_flag_updates),
	DEF_BOOL(pop3_enable_last),
	DEF_BOOL(pop3_reuse_xuidl),
	DEF_BOOL(pop3_lock_session),
	DEF_STR(pop3_uidl_format),
	DEF_STR(pop3_client_workarounds),
	DEF_STR(pop3_logout_format),

	{ 0, NULL, 0 }
};
