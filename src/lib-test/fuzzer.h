#ifndef FUZZER_H
#define FUZZER_H

#define FUZZ_BEGIN_DATA(data_arg, size_arg) \
	int LLVMFuzzerTestOneInput(data_arg, size_arg); \
	int LLVMFuzzerTestOneInput(data_arg, size_arg) { \
		fuzzer_init(); T_BEGIN {

#define FUZZ_BEGIN_STR(str_arg) \
	int LLVMFuzzerTestOneInput(const uint8_t *_param_data, size_t _param_size); \
	int LLVMFuzzerTestOneInput(const uint8_t *_param_data, size_t _param_size) { \
		fuzzer_init(); \
		T_BEGIN { str_arg = t_strndup(_param_data, _param_size);

#define FUZZ_BEGIN_FD(fd_arg, ioloop_arg) \
	FUZZ_BEGIN_DATA(const uint8_t *_param_data, size_t _param_size) \
	ioloop_arg = io_loop_create(); \
	fd_arg = fuzzer_io_as_fd(_param_data, _param_size);

#define FUZZ_END \
	} T_END; return 0; }

void fuzzer_init(void);

int fuzzer_io_as_fd(const uint8_t *data, size_t size);

#endif
