#ifndef IOSTREAM_ZSTD_PRIVATE_H
#define IOSTREAM_ZSTD_PRIVATE_H 1

/* a horrible hack to fix issues when the installed libzstd is lot
   newer than what we were compiled against. */
static inline ZSTD_ErrorCode zstd_version_errcode(ZSTD_ErrorCode err)
{
#if ZSTD_VERSION_NUMBER < 10301
	if (ZSTD_versionNumber() > 10300) {
		/* reinterpret them */
		if (err == 10)
			return ZSTD_error_prefix_unknown;
		if (err == 32)
			return ZSTD_error_dictionary_wrong;
		if (err == 62)
			return ZSTD_error_init_missing;
		if (err == 64)
			return ZSTD_error_memory_allocation;
		return ZSTD_error_GENERIC;
	}
#endif
	return err;
}

#endif
