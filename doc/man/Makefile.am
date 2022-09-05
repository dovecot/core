static_mans = \
	deliver.1 \
	doveadm-backup.1 \
	doveadm-config.1 \
	doveadm-copy.1 \
	doveadm-reload.1 \
	doveadm-stop.1

dist_man1_MANS = \
	deliver.1 \
	doveadm-backup.1 \
	doveadm-config.1 \
	doveadm-copy.1 \
	doveadm-reload.1 \
	doveadm-stop.1 \
	doveadm.1 \
	doveadm-acl.1 \
	doveadm-altmove.1 \
	doveadm-auth.1 \
	doveadm-deduplicate.1 \
	doveadm-director.1 \
	doveadm-dump.1 \
	doveadm-exec.1 \
	doveadm-expunge.1 \
	doveadm-fetch.1 \
	doveadm-flags.1 \
	doveadm-fs.1 \
	doveadm-fts.1 \
	doveadm-import.1 \
	doveadm-indexer.1 \
	doveadm-instance.1 \
	doveadm-index.1 \
	doveadm-force-resync.1 \
	doveadm-help.1 \
	doveadm-kick.1 \
	doveadm-log.1 \
	doveadm-mailbox.1 \
	doveadm-mailbox-cryptokey.1 \
	doveadm-move.1 \
	doveadm-penalty.1 \
	doveadm-proxy.1 \
	doveadm-purge.1 \
	doveadm-pw.1 \
	doveadm-quota.1 \
	doveadm-rebuild.1 \
	doveadm-replicator.1 \
	doveadm-save.1 \
	doveadm-search.1 \
	doveadm-stats.1 \
	doveadm-sync.1 \
	doveadm-user.1 \
	doveadm-who.1 \
	doveconf.1 \
	dovecot.1 \
	dovecot-lda.1 \
	dovecot-sysreport.1

dist_man7_MANS = \
	doveadm-search-query.7

rebuild:
	for page in *.1 *.7; do \
	  if ! echo "$(static_mans)" | grep -qF "$$page"; then \
	    rm -f $$page; \
	  fi \
	done

distclean-local: rebuild
