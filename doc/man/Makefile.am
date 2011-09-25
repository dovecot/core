pkgsysconfdir = $(sysconfdir)/dovecot

dist_man1_MANS = \
	deliver.1 \
	doveadm-config.1 \
	doveadm-reload.1 \
	doveadm-stop.1

dist_man7_MANS = \
	doveadm-search-query.7

nodist_man1_MANS = \
	doveadm.1 \
	doveadm-altmove.1 \
	doveadm-auth.1 \
	doveadm-director.1 \
	doveadm-dump.1 \
	doveadm-expunge.1 \
	doveadm-fetch.1 \
	doveadm-import.1 \
	doveadm-index.1 \
	doveadm-force-resync.1 \
	doveadm-help.1 \
	doveadm-kick.1 \
	doveadm-log.1 \
	doveadm-mailbox.1 \
	doveadm-move.1 \
	doveadm-penalty.1 \
	doveadm-purge.1 \
	doveadm-pw.1 \
	doveadm-quota.1 \
	doveadm-search.1 \
	doveadm-user.1 \
	doveadm-who.1 \
	doveconf.1 \
	dovecot.1 \
	dovecot-lda.1 \
	dsync.1

man_includefiles = \
	$(srcdir)/global-options-formatter.inc \
	$(srcdir)/global-options.inc \
	$(srcdir)/option-A.inc \
	$(srcdir)/option-S-socket.inc \
	$(srcdir)/option-u-user.inc \
	$(srcdir)/reporting-bugs.inc

EXTRA_DIST = \
	doveadm.1.in \
	doveadm-altmove.1.in \
	doveadm-auth.1.in \
	doveadm-director.1.in \
	doveadm-dump.1.in \
	doveadm-expunge.1.in \
	doveadm-fetch.1.in \
	doveadm-import.1.in \
	doveadm-index.1.in \
	doveadm-force-resync.1.in \
	doveadm-help.1.in \
	doveadm-kick.1.in \
	doveadm-log.1.in \
	doveadm-mailbox.1.in \
	doveadm-move.1.in \
	doveadm-penalty.1.in \
	doveadm-purge.1.in \
	doveadm-pw.1.in \
	doveadm-quota.1.in \
	doveadm-search.1.in \
	doveadm-user.1.in \
	doveadm-who.1.in \
	doveconf.1.in \
	dovecot.1.in \
	dovecot-lda.1.in \
	dsync.1.in \
	sed.sh \
	$(man_includefiles)

CLEANFILES = $(nodist_man1_MANS)

doveadm.1: $(srcdir)/doveadm.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm.1.in > doveadm.1

doveadm-altmove.1: $(srcdir)/doveadm-altmove.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-altmove.1.in > doveadm-altmove.1

doveadm-auth.1: $(srcdir)/doveadm-auth.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-auth.1.in > doveadm-auth.1

doveadm-director.1: $(srcdir)/doveadm-director.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-director.1.in > doveadm-director.1

doveadm-dump.1: $(srcdir)/doveadm-dump.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-dump.1.in > doveadm-dump.1

doveadm-expunge.1: $(srcdir)/doveadm-expunge.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-expunge.1.in > doveadm-expunge.1

doveadm-fetch.1: $(srcdir)/doveadm-fetch.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-fetch.1.in > doveadm-fetch.1

doveadm-import.1: $(srcdir)/doveadm-import.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-import.1.in > doveadm-import.1

doveadm-index.1: $(srcdir)/doveadm-index.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-index.1.in > doveadm-index.1

doveadm-force-resync.1: $(srcdir)/doveadm-force-resync.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-force-resync.1.in > doveadm-force-resync.1

doveadm-help.1: $(srcdir)/doveadm-help.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-help.1.in > doveadm-help.1

doveadm-kick.1: $(srcdir)/doveadm-kick.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-kick.1.in > doveadm-kick.1

doveadm-log.1: $(srcdir)/doveadm-log.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-log.1.in > doveadm-log.1

doveadm-mailbox.1: $(srcdir)/doveadm-mailbox.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-mailbox.1.in > doveadm-mailbox.1

doveadm-move.1: $(srcdir)/doveadm-move.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-move.1.in > doveadm-move.1

doveadm-penalty.1: $(srcdir)/doveadm-penalty.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-penalty.1.in > doveadm-penalty.1

doveadm-purge.1: $(srcdir)/doveadm-purge.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-purge.1.in > doveadm-purge.1

doveadm-pw.1: $(srcdir)/doveadm-pw.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-pw.1.in > doveadm-pw.1

doveadm-quota.1: $(srcdir)/doveadm-quota.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-quota.1.in > doveadm-quota.1

doveadm-search.1: $(srcdir)/doveadm-search.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-search.1.in > doveadm-search.1

doveadm-user.1: $(srcdir)/doveadm-user.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-user.1.in > doveadm-user.1

doveadm-who.1: $(srcdir)/doveadm-who.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveadm-who.1.in > doveadm-who.1

doveconf.1: $(srcdir)/doveconf.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/doveconf.1.in > doveconf.1

dovecot.1: $(srcdir)/dovecot.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/dovecot.1.in > dovecot.1

dovecot-lda.1: $(srcdir)/dovecot-lda.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/dovecot-lda.1.in > dovecot-lda.1

dsync.1: $(srcdir)/dsync.1.in $(man_includefiles) Makefile
	$(SHELL) $(srcdir)/sed.sh $(srcdir) $(rundir) $(pkgsysconfdir) \
		< $(srcdir)/dsync.1.in > dsync.1
