#ifndef DOVEADM_FTS_H
#define DOVEADM_FTS_H

struct module;

void doveadm_dump_fts_expunge_log_init(void);

void doveadm_fts_plugin_init(struct module *module);
void doveadm_fts_plugin_deinit(void);

#endif
