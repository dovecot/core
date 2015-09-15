#ifndef ISTREAM_FS_STATS_H
#define ISTREAM_FS_STATS_H

struct fs_file;

struct istream *
i_stream_create_fs_stats(struct istream *input, struct fs_file *file);

#endif
