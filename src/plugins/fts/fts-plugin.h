#ifndef FTS_PLUGIN_H
#define FTS_PLUGIN_H

extern void (*fts_next_hook_mailbox_allocated)(struct mailbox *box);

void fts_mailbox_allocated(struct mailbox *box);

void fts_plugin_init(void);
void fts_plugin_deinit(void);

#endif
