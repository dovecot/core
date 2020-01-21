pkgsysconfdir = $(sysconfdir)/dovecot

SUFFIXES = .1.in .1

dist_man1_MANS = \
	deliver.1 \
	doveadm-backup.1 \
	doveadm-config.1 \
	doveadm-copy.1 \
	doveadm-reload.1 \
	doveadm-stop.1 \
	dsync.1

dist_man7_MANS = \
	doveadm-search-query.7

nodist_man1_MANS = \
	doveadm.1 \
	doveadm-acl.1 \
	doveadm-altmove.1 \
	doveadm-auth.1 \
	doveadm-batch.1 \
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

man_includefiles = \
	$(srcdir)/global-options-formatter.inc \
	$(srcdir)/global-options.inc \
	$(srcdir)/option-A.inc \
	$(srcdir)/option-F-file.inc \
	$(srcdir)/option-S-socket.inc \
	$(srcdir)/option-u-user.inc \
	$(srcdir)/reporting-bugs.inc

EXTRA_DIST = \
	doveadm.1.in \
	doveadm-acl.1.in \
	doveadm-altmove.1.in \
	doveadm-auth.1.in \
	doveadm-batch.1.in \
	doveadm-deduplicate.1.in \
	doveadm-director.1.in \
	doveadm-dump.1.in \
	doveadm-exec.1.in \
	doveadm-expunge.1.in \
	doveadm-fetch.1.in \
	doveadm-flags.1.in \
	doveadm-fs.1.in \
	doveadm-fts.1.in \
	doveadm-import.1.in \
	doveadm-instance.1.in \
	doveadm-index.1.in \
	doveadm-force-resync.1.in \
	doveadm-help.1.in \
	doveadm-kick.1.in \
	doveadm-log.1.in \
	doveadm-mailbox.1.in \
	doveadm-mailbox-cryptokey.1.in \
	doveadm-move.1.in \
	doveadm-penalty.1.in \
	doveadm-proxy.1.in \
	doveadm-purge.1.in \
	doveadm-pw.1.in \
	doveadm-quota.1.in \
	doveadm-rebuild.1.in \
	doveadm-replicator.1.in \
	doveadm-save.1.in \
	doveadm-search.1.in \
	doveadm-stats.1.in \
	doveadm-sync.1.in \
	doveadm-user.1.in \
	doveadm-who.1.in \
	doveconf.1.in \
	dovecot.1.in \
	dovecot-lda.1.in \
	dovecot-sysreport.1.in \
	sed.sh \
	$(man_includefiles)

CLEANFILES = $(nodist_man1_MANS)

.1.in.1: $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		$(pkglibexecdir) < $< > $@
