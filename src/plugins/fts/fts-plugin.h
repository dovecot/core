#ifndef FTS_PLUGIN_H
#define FTS_PLUGIN_H

void fts_mailbox_allocated(struct mailbox *box);

void fts_plugin_init(struct module *module);
void fts_plugin_deinit(void);

#endif
