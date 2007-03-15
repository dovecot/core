/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "write-full.h"
#include "seq-range-array.h"
#include "bsearch-insert-pos.h"
#include "dbox-file.h"
#include "dbox-storage.h"
#include "dbox-keywords.h"

#include <stdlib.h>

static int dbox_keyword_map_compare(const void *p1, const void *p2)
{
	const struct keyword_map *map1 = p1, *map2 = p2;

	return map1->index_idx < map2->index_idx ? -1 :
		map1->index_idx > map2->index_idx ? 1 : 0;
}

int dbox_file_read_keywords(struct dbox_mailbox *mbox, struct dbox_file *file)
{
	struct keyword_map *map, kw;
	const char *line;
	unsigned int idx, count, insert_idx;
	uoff_t last_offset;

	if (array_is_created(&file->idx_file_keywords)) {
		array_clear(&file->idx_file_keywords);
		array_clear(&file->file_idx_keywords);
	} else {
		i_array_init(&file->idx_file_keywords, file->keyword_count);
		i_array_init(&file->file_idx_keywords, file->keyword_count);
	}

	/* currently we assume that all extra space at the end of header
	   belongs to keyword list. */
	file->keyword_list_size_alloc =
		file->header_size - file->keyword_list_offset;

	i_stream_seek(file->input, file->keyword_list_offset);
	idx = 0;
	last_offset = file->input->v_offset;
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == '\0') {
			/* end of list */
			break;
		}
		last_offset = file->input->v_offset;

		/* set up map record for the keyword */
		(void)mail_index_keyword_lookup(mbox->ibox.index, line, TRUE,
						&kw.index_idx);
		kw.file_idx = idx;

		/* look up the position where to insert it */
		map = array_get_modifiable(&file->idx_file_keywords, &count);
		if (idx == 0)
			insert_idx = 0;
		else {
			bsearch_insert_pos(&kw, map, count, sizeof(*map),
					   dbox_keyword_map_compare,
					   &insert_idx);
		}
		array_insert(&file->idx_file_keywords, insert_idx, &kw, 1);
		array_append(&file->file_idx_keywords, &kw.index_idx, 1);

		if (++idx == file->keyword_count)
			break;
	}

	if (line == NULL || file->input->v_offset > file->header_size) {
		/* unexpected end of list, or list continues outside its
		   allocated area */
		mail_storage_set_critical(STORAGE(mbox->storage),
			"Corrupted keyword list offset in dbox file %s",
			file->path);
		array_clear(&file->idx_file_keywords);
		return 0;
	}

	file->keyword_list_size_used =
		last_offset - file->keyword_list_offset;
	return 1;
}

static int keyword_lookup_cmp(const void *key, const void *obj)
{
	const unsigned int *index_idx = key;
	const struct keyword_map *map = obj;

	return *index_idx < map->index_idx ? -1 :
		*index_idx > map->index_idx ? 1 : 0;
}

bool dbox_file_lookup_keyword(struct dbox_mailbox *mbox, struct dbox_file *file,
			      unsigned int index_idx, unsigned int *idx_r)
{
	const struct keyword_map *map, *pos;
	unsigned int count;

	if (!array_is_created(&file->idx_file_keywords)) {
		/* Read the keywords, if there are any */
		if (dbox_file_read_keywords(mbox, file) <= 0)
			return FALSE;
	}

	map = array_get(&file->idx_file_keywords, &count);
	pos = bsearch(&index_idx, map, count, sizeof(*map),
		      keyword_lookup_cmp);
	if (pos != NULL && idx_r != NULL)
		*idx_r = pos->file_idx;
	return pos != NULL;
}

int dbox_file_append_keywords(struct dbox_mailbox *mbox, struct dbox_file *file,
			      const struct seq_range *idx_range,
			      unsigned int count)
{
	const ARRAY_TYPE(keywords) *idx_keywords;
	string_t *keyword_str;
	const char *const *idx_keyword_names;
	unsigned int i, idx_keyword_count, new_pos;
	int ret;

	t_push();
	keyword_str = t_str_new(2048);
	idx_keywords = mail_index_get_keywords(mbox->ibox.index);
	idx_keyword_names = array_get(idx_keywords, &idx_keyword_count);

	/* make sure we've read the existing keywords */
	if (!array_is_created(&file->idx_file_keywords)) {
		ret = dbox_file_read_keywords(mbox, file);
		if (ret < 0)
			return -1;

		if (ret == 0) {
			/* broken keywords list. */
			file->keyword_list_size_used = 0;
		}
	}

	/* append existing keywords */
	if (array_count(&file->idx_file_keywords) > 0) {
		const unsigned int *file_idx;
		unsigned int file_count;

		file_idx = array_get(&file->file_idx_keywords, &file_count);
		for (i = 0; i < file_count; i++) {
			i_assert(file_idx[i] < idx_keyword_count);

			str_append(keyword_str, idx_keyword_names[file_idx[i]]);
			str_append_c(keyword_str, '\n');
		}
	}

	/* append new keywords */
	if (file->keyword_list_size_used == 0)
		new_pos = 0;
	else {
		new_pos = str_len(keyword_str);
		i_assert(new_pos == file->keyword_list_size_used);
	}
	for (i = 0; i < count; i++) {
		unsigned int idx;

		for (idx = idx_range[i].seq1; idx <= idx_range[i].seq2; idx++) {
			size_t prev_len;

			i_assert(idx < idx_keyword_count);
			i_assert(!dbox_file_lookup_keyword(mbox, file,
							   idx, NULL));

			prev_len = str_len(keyword_str);
			str_append(keyword_str, idx_keyword_names[idx]);
			str_append_c(keyword_str, '\n');

			if (str_len(keyword_str) >=
			    file->keyword_list_size_alloc) {
				/* FIXME: keyword list doesn't fit to the
				   space allocated for it. create a new file
				   where there's more space for keywords and
				   move the mails there.

				   for now we'll just ignore the problem. */
				str_truncate(keyword_str, prev_len);
				break;
			}
		}
	}

	str_append_c(keyword_str, '\n');
	i_assert(str_len(keyword_str) <= file->keyword_list_size_alloc);
	i_assert(new_pos < str_len(keyword_str));

	/* we can reuse the existing keyword list position */
	if (pwrite_full(file->fd, str_data(keyword_str) + new_pos,
			str_len(keyword_str) - new_pos,
			file->keyword_list_offset + new_pos) < 0) {
		mail_storage_set_critical(STORAGE(mbox->storage),
			"pwrite_full(%s) failed: %m", file->path);
	}

	/* FIXME: we could do this faster than by reading them.. */
	ret = 0;
	if (dbox_file_read_keywords(mbox, file) <= 0)
		ret = -1;

	t_pop();
	return ret;
}
