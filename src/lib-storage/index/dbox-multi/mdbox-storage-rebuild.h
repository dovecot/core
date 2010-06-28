#ifndef MDBOX_STORAGE_REBUILD_H
#define MDBOX_STORAGE_REBUILD_H

struct mdbox_map_atomic_context;

int mdbox_storage_rebuild_in_context(struct mdbox_storage *storage,
				     struct mdbox_map_atomic_context *atomic);
int mdbox_storage_rebuild(struct mdbox_storage *storage);

#endif
