#ifndef IMAP_QUOTA_PLUGIN_H
#define IMAP_QUOTA_PLUGIN_H

extern const char *imap_quota_plugin_dependencies[];

void imap_quota_plugin_init(void);
void imap_quota_plugin_deinit(void);

#endif
