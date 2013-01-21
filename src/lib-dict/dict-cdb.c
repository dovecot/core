/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef BUILD_CDB
#include "dict-private.h"

#include <string.h>
#include <cdb.h>
#include <unistd.h>
#include <fcntl.h>

#define CDB_WITH_NULL 1
#define CDB_WITHOUT_NULL 2

struct cdb_dict {
	struct dict dict;
	struct cdb cdb;
	char *path;
	int fd, flag;
};

static void cdb_dict_deinit(struct dict *_dict);

static int
cdb_dict_init(struct dict *driver, const char *uri,
	      enum dict_data_type value_type ATTR_UNUSED,
	      const char *username ATTR_UNUSED,
	      const char *base_dir ATTR_UNUSED,
	      struct dict **dict_r, const char **error_r)
{
	struct cdb_dict *dict;

	dict = i_new(struct cdb_dict, 1);
	dict->dict = *driver;
	dict->path = i_strdup(uri);
	dict->flag = CDB_WITH_NULL | CDB_WITHOUT_NULL;

	/* initialize cdb to 0 (unallocated) */
	memset(&dict->cdb, 0, sizeof(struct cdb));

	dict->fd = open(dict->path, O_RDONLY);
	if (dict->fd == -1) {
		*error_r = t_strdup_printf("open(%s) failed: %m", dict->path);
		cdb_dict_deinit(&dict->dict);
		return -1;
	}

#ifdef TINYCDB_VERSION
	if (cdb_init(&dict->cdb, dict->fd) < 0) {
		*error_r = t_strdup_printf("cdb_init(%s) failed: %m", dict->path);
		cdb_dict_deinit(&dict->dict);
		return -1;
	}
#else
	cdb_init(&dict->cdb, dict->fd);
#endif

	*dict_r = &dict->dict;
	return 0;
}

static void cdb_dict_deinit(struct dict *_dict)
{
	struct cdb_dict *dict = (struct cdb_dict *)_dict;

	/* we can safely deinit unallocated cdb */
	cdb_free(&dict->cdb);

	if (dict->fd != -1) {
		if (close(dict->fd) < 0)
			i_error("close(%s) failed: %m", dict->path);
	}

	i_free(dict->path);
	i_free(dict);
}

static int cdb_dict_lookup(struct dict *_dict, pool_t pool,
			   const char *key, const char **value_r)
{
	struct cdb_dict *dict = (struct cdb_dict *)_dict;
	unsigned datalen;
	int ret = 0;
	char *data;

	/* keys and values may be null terminated... */
	if ((dict->flag & CDB_WITH_NULL) != 0) {
		ret = cdb_find(&dict->cdb, key, (unsigned)strlen(key)+1);
		if (ret > 0)
			dict->flag &= ~CDB_WITHOUT_NULL;
	}

	/* ...or not */
	if (ret == 0 && (dict->flag & CDB_WITHOUT_NULL) != 0) {
		ret = cdb_find(&dict->cdb, key, (unsigned)strlen(key));
		if (ret > 0)
			dict->flag &= ~CDB_WITH_NULL;
	}

	if (ret <= 0) {
		*value_r = NULL;
		/* something bad with db */
		if (ret < 0) {
			i_error("cdb_find(%s) failed: %m", dict->path);
			return -1;
		}
		/* found nothing */
		return 0;
	}

	datalen = cdb_datalen(&dict->cdb);
	data = p_malloc(pool, datalen + 1);
	if (cdb_read(&dict->cdb, data, datalen, cdb_datapos(&dict->cdb)) < 0) {
		i_error("cdb_read(%s) failed: %m", dict->path);
		return -1;
	}
	*value_r = data;
	return 1;
}

struct dict dict_driver_cdb = {
	.name = "cdb",
	{
		cdb_dict_init,
		cdb_dict_deinit,
		NULL,
		cdb_dict_lookup,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	}
};
#endif
