#ifndef ISTREAM_FS_FILE_H
#define ISTREAM_FS_FILE_H

struct fs_file;

/* Open the given file only when something is actually tried to be read from
   the stream. The file is automatically deinitialized when the stream is
   destroyed (which is why it's also set to NULL so it's not accidentally
   double-freed). */
struct istream *
i_stream_create_fs_file(struct fs_file **file, size_t max_buffer_size);

#endif
