#ifndef __DICT_CACHE_H
#define __DICT_CACHE_H

struct dict_cache *dict_cache_init(void);
void dict_cache_deinit(struct dict_cache *cache);

struct dict *dict_cache_get(struct dict_cache *cache, const char *uri);
void dict_cache_unref(struct dict_cache *cache, const char *uri);

#endif
