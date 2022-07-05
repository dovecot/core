#ifndef FUZZER_H
#define FUZZER_H

struct iostream_pump;
struct ioloop;

struct fuzzer_context {
	int fd, fd_pump;
	struct iostream_pump *pump;
	struct ioloop *ioloop;
};

#define FUZZ_BEGIN_DATA(data_arg, size_arg) \
	int LLVMFuzzerTestOneInput(data_arg, size_arg); \
	int LLVMFuzzerTestOneInput(data_arg, size_arg) { \
		struct fuzzer_context fuzz_ctx; \
		fuzzer_init(&fuzz_ctx); T_BEGIN {

const char *fuzzer_t_strndup_replace_zero(
	const uint8_t *_param_data, size_t _param_size, char subst);

#define FUZZ_BEGIN_STR(str_arg) \
	FUZZ_BEGIN_DATA(const uint8_t *_param_data, size_t _param_size) \
	str_arg = fuzzer_t_strndup_replace_zero(_param_data, _param_size, '\\');

#define FUZZ_BEGIN_FD \
	FUZZ_BEGIN_DATA(const uint8_t *_param_data, size_t _param_size) \
	fuzz_ctx.ioloop = io_loop_create(); \
	(void)fuzzer_io_as_fd(&fuzz_ctx, _param_data, _param_size);

#define FUZZ_END \
	} T_END; fuzzer_deinit(&fuzz_ctx); return 0; }

void fuzzer_init(struct fuzzer_context *fuzz_ctx);
void fuzzer_deinit(struct fuzzer_context *fuzz_ctx);

int fuzzer_io_as_fd(struct fuzzer_context *fuzz_ctx,
		    const uint8_t *data, size_t size);

#endif
