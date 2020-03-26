#ifndef FUZZER_H
#define FUZZER_H

#define FUZZ_BEGIN_DATA(data_arg, size_arg) \
	int LLVMFuzzerTestOneInput(data_arg, size_arg); \
	int LLVMFuzzerTestOneInput(data_arg, size_arg) { \
		T_BEGIN {

#define FUZZ_BEGIN_STR(str_arg) \
	int LLVMFuzzerTestOneInput(const uint8_t *_param_data, size_t _param_size); \
	int LLVMFuzzerTestOneInput(const uint8_t *_param_data, size_t _param_size) { \
		T_BEGIN { str_arg = t_strndup(_param_data, _param_size);

#define FUZZ_END \
	} T_END; return 0; }

#endif
