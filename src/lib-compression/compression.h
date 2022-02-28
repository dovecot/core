#ifndef COMPRESSION_H
#define COMPRESSION_H

enum istream_decompress_flags {
	/* If stream isn't detected to be compressed, return it as passthrough
	   istream. */
	ISTREAM_DECOMPRESS_FLAG_TRY = BIT(0),
};

struct compression_handler {
	const char *name;
	const char *ext;
	bool (*is_compressed)(struct istream *input);
	struct istream *(*create_istream)(struct istream *input);
	struct ostream *(*create_ostream)(struct ostream *output, int level);
	/* returns minimum level */
	int (*get_min_level)(void);
	/* the default can be -1 (e.g. gz), so the return value of this has to
	   be used as-is. */
	int (*get_default_level)(void);
	/* returns maximum level */
	int (*get_max_level)(void);
};

extern const struct compression_handler compression_handlers[];

/* Returns 1 if compression handler was found and is usable, 0 if support isn't
   compiled in, -1 if unknown. */
int compression_lookup_handler(const char *name,
			       const struct compression_handler **handler_r);
/* Detect handler by looking at the first few bytes of the input stream. */
const struct compression_handler *
compression_detect_handler(struct istream *input);
/* Lookup handler based on filename extension in the path, returns the same
 * values as compression_lookup_handler. */
int compression_lookup_handler_from_ext(const char *path,
					const struct compression_handler **handler_r);

/* Automatically detect the compression format. Note that using tee-istream as
   one of the parent streams is dangerous here: A decompression istream may
   have to read a lot of data (e.g. 8 kB isn't enough) before it returns even
   the first byte as output. If the other tee children aren't read forward,
   this can cause an infinite loop when i_stream_read() is always returning 0.
   This is why ISTREAM_DECOMPRESS_FLAG_TRY should be used instead of attempting
   to implement similar functionality with tee-istream. */
struct istream *
i_stream_create_decompress(struct istream *input,
			   enum istream_decompress_flags flags);

#endif
