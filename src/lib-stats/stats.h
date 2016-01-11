#ifndef STATS_H
#define STATS_H

struct stats;
struct stats_item;

struct stats_vfuncs {
	const char *short_name;

	size_t (*alloc_size)(void);
	unsigned int (*field_count)(void);
	const char *(*field_name)(unsigned int n);
	void (*field_value)(string_t *str, const struct stats *stats,
			    unsigned int n);

	bool (*diff)(const struct stats *stats1, const struct stats *stats2,
		     struct stats *diff_stats_r, const char **error_r);
	void (*add)(struct stats *dest, const struct stats *src);
	bool (*have_changed)(const struct stats *prev, const struct stats *cur);

	void (*export)(buffer_t *buf, const struct stats *stats);
	bool (*import)(const unsigned char *data, size_t size, size_t *pos_r,
		       struct stats *stats, const char **error_r);
};

struct stats_item *stats_register(const struct stats_vfuncs *vfuncs);
void stats_unregister(struct stats_item **item);

/* Allocate struct stats from a given pool. */
struct stats *stats_alloc(pool_t pool);
/* Returns the number of bytes allocated to stats. */
size_t stats_alloc_size(void);
/* Copy all stats from src to dest. */
void stats_copy(struct stats *dest, const struct stats *src);

/* Returns the number of stats fields. */
unsigned int stats_field_count(void);
/* Returns the name of a stats field (exported to doveadm). */
const char *stats_field_name(unsigned int n);
/* Returns the value of a stats field as a string (exported to doveadm). */
void stats_field_value(string_t *str, const struct stats *stats,
		       unsigned int n);

/* Return diff_stats_r->field = stats2->field - stats1->field.
   diff1 is supposed to have smaller values than diff2. Returns TRUE if this
   is so, FALSE if not */
bool stats_diff(const struct stats *stats1, const struct stats *stats2,
		struct stats *diff_stats_r, const char **error_r);
/* dest->field += src->field */
void stats_add(struct stats *dest, const struct stats *src);
/* Returns TRUE if any fields have changed in cur since prev in a way that
   a plugin should send the updated statistics to the stats process. Not all
   fields necessarily require sending an update. */
bool stats_have_changed(const struct stats *prev, const struct stats *cur);

/* Export stats into a buffer in binary format. */
void stats_export(buffer_t *buf, const struct stats *stats);
/* Import stats from a buffer. The buffer doesn't need to contain an update to
   all the stats items - old_stats are used for that item in such case.
   Currently it's not allowed to have unknown items in the buffer. */
bool stats_import(const unsigned char *data, size_t size,
		  const struct stats *old_stats, struct stats *stats,
		  const char **error_r);
/* Return a pointer to stats where the specified item starts. The returned
   pointer can be used to fill up the item-specific stats (up to its
   alloc_size() number of bytes). */
void *stats_fill_ptr(struct stats *stats, struct stats_item *item);

void stats_reset(struct stats *stats);

#endif
