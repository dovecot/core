#ifndef IMAP_STATS_H
#define IMAP_STATS_H

/* Statistics that are used in the imap_logout_format message. */
struct imap_logout_stats {
	unsigned int fetch_hdr_count, fetch_body_count;
	uint64_t fetch_hdr_bytes, fetch_body_bytes;
	unsigned int deleted_count, expunged_count, trashed_count;
	unsigned int autoexpunged_count, append_count;
	uoff_t input_bytes_extra, output_bytes_extra;
};

#endif /* IMAP_STATS_H */
