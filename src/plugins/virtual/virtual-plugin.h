#ifndef VIRTUAL_PLUGIN_H
#define VIRTUAL_PLUGIN_H

void virtual_mailbox_list_created(struct mailbox_list *list);

void virtual_plugin_init(struct module *module);
void virtual_plugin_deinit(void);

#endif
