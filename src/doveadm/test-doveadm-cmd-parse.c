/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "doveadm.h"
#include "doveadm-cmd-parse.h"

static inline void
assert_param_bool(struct doveadm_cmd_context *cctx, const char *name,
		  bool expected)
{
	test_assert_cmp(expected, ==, doveadm_cmd_param_flag(cctx, name));
}

static void
assert_param_str(struct doveadm_cmd_context *cctx, const char *name,
		 const char* expected)
{
	const char *value;
	if (!doveadm_cmd_param_str(cctx, name, &value)) {
		if (expected != NULL)
			test_failed(t_strdup_printf(
				"doveadm_cmd_param_str(%s) failed", name));
	}
	else
		test_assert_strcmp(expected, value);
}

static void test_case(const char *name, int expected_rc,
                      doveadm_command_ver2_t assertfn,
		      struct doveadm_cmd_ver2 *cmd,const char **argv )
{
	T_BEGIN {
		test_begin(name);

		struct doveadm_cmd_ver2 *cmds = t_new(struct doveadm_cmd_ver2, 2);
		struct doveadm_cmd_context *cctx = t_new(struct doveadm_cmd_context, 1);

		cmd->cmd = assertfn;
		cmds[0] = *cmd;
		cctx->cmd = cmds;
		cctx->event = event_create(NULL);

		if (expected_rc < 0)
			test_expect_errors(1);

		int actual_rc = doveadm_cmdline_run(
			str_array_length(argv), argv, cctx);

		test_assert_cmp(expected_rc, ==, actual_rc);
		event_unref(&cctx->event);
		test_end();
	} T_END;
}

struct doveadm_cmd_ver2 cmdv2_posargs = {
	.flags = 0,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "pos1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "pos2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 cmdv2_kvargs = {
	.flags = 0,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "pos1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "key2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "pos2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 cmdv2_kvpositions = {
	.flags = 0,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "pos1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "key2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "pos2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key3", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "key4", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_KEY_VALUE)
DOVEADM_CMD_PARAM('\0', "pos3", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 cmdv2_switches = {
	.flags = 0,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('1', "switch1", CMD_PARAM_BOOL, CMD_PARAM_FLAG_NONE)
DOVEADM_CMD_PARAM('2', "switch2", CMD_PARAM_STR, CMD_PARAM_FLAG_NONE)
DOVEADM_CMD_PARAM('\0', "pos1", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "pos2", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

static void assert_no_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", NULL);
	assert_param_str(cctx, "pos2", NULL);
}

static void assert_1_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", "arg1");
	assert_param_str(cctx, "pos2", NULL);
}

static void assert_2_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", "arg1");
	assert_param_str(cctx, "pos2", "arg2");
}

static void assert_3_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", "arg1");
	assert_param_str(cctx, "pos2", "arg2");
	assert_param_str(cctx, "pos3", "arg3");
}

static void assert_kv1_in_pos12(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", "key1");
	assert_param_str(cctx, "pos2", "value1");
}

static void assert_kv3_in_pos23(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "pos1", "arg1");
	assert_param_str(cctx, "pos2", "key3");
	assert_param_str(cctx, "pos3", "value3");
}

static void assert_key12(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "key1", "value1");
	assert_param_str(cctx, "key2", "value2");
}

static void assert_key34(struct doveadm_cmd_context *cctx)
{
	assert_param_str(cctx, "key3", "value3");
	assert_param_str(cctx, "key4", "value4");
}

static void assert_key12_1_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_1_pos_args(cctx);
	assert_key12(cctx);
}

static void assert_key12_2_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_2_pos_args(cctx);
	assert_key12(cctx);
}

static void assert_key1234_2_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_2_pos_args(cctx);
	assert_key12(cctx);
	assert_key34(cctx);
}

static void assert_no_switch12(struct doveadm_cmd_context *cctx)
{
	assert_param_bool(cctx, "switch1", FALSE);
	assert_param_str(cctx, "switch2", NULL);
}

static void assert_switch12(struct doveadm_cmd_context *cctx)
{
	assert_param_bool(cctx, "switch1", TRUE);
	assert_param_str(cctx, "switch2", "value2");
}

static void assert_no_switch_no_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_no_pos_args(cctx);
	assert_no_switch12(cctx);
}

static void assert_no_switch_1_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_1_pos_args(cctx);
	assert_no_switch12(cctx);
}

static void assert_switch12_1_pos_args(struct doveadm_cmd_context *cctx)
{
	assert_1_pos_args(cctx);
	assert_switch12(cctx);
}

static void assert_not_execd(struct doveadm_cmd_context *cctx ATTR_UNUSED)
{
	test_failed("doveadm_cmdline_run() expected to fail and not execute the cmd");
}

#define line(l) t_strsplit_spaces(l, " ")

static void test_posargs(void)
{
	test_case("pos_0args", 0, assert_no_pos_args, &cmdv2_posargs,
		line("cmd"));
	test_case("pos_1args", 0, assert_1_pos_args,  &cmdv2_posargs,
		line("cmd arg1"));
	test_case("pos_2args", 0, assert_2_pos_args,  &cmdv2_posargs,
		line("cmd arg1 arg2"));
	test_case("pos_3args", -1, assert_not_execd,  &cmdv2_posargs,
		line("cmd arg1 arg2 arg3"));
}

static void test_kvargs(void)
{
	test_case("kv_0args", 0, assert_no_pos_args, &cmdv2_kvargs,
		line("cmd"));
	test_case("kv_1args", 0, assert_1_pos_args,  &cmdv2_kvargs,
		line("cmd arg1"));
	test_case("kv_2args", 0, assert_2_pos_args,  &cmdv2_kvargs,
		line("cmd arg1 arg2"));
	test_case("kv_3args", -1, assert_not_execd,  &cmdv2_kvargs,
		line("cmd arg1 arg2 arg3"));

	/* not in expected position, named args are expected in 2nd arg position not 1st */
	test_case("kv_early", 0, assert_kv1_in_pos12, &cmdv2_kvargs,
		line("cmd key1 value1"));

	/* not in expected position, named args are expected in 2nd arg position not 3rd */
	test_case("kv_late", -1, assert_not_execd, &cmdv2_kvargs,
		line("cmd arg1 arg2 key1 value1"));

	test_case("kv_k12_1args", 0, assert_key12_1_pos_args, &cmdv2_kvargs,
		line("cmd arg1 key1 value1 key2 value2"));
	test_case("kv_k21_1args", 0, assert_key12_1_pos_args, &cmdv2_kvargs,
		line("cmd arg1 key2 value2 key1 value1"));

	test_case("kv_k12_2args", 0, assert_key12_2_pos_args, &cmdv2_kvargs,
		line("cmd arg1 key1 value1 key2 value2 arg2"));
	test_case("kv_k21_2args", 0, assert_key12_2_pos_args, &cmdv2_kvargs,
		line("cmd arg1 key2 value2 key1 value1 arg2"));
}

static void test_kvpos(void)
{
	test_case("kvpos_3args", 0, assert_3_pos_args, &cmdv2_kvpositions,
		line("cmd arg1 arg2 arg3"));
	test_case("kvpos_k12_k43", 0, assert_key1234_2_pos_args, &cmdv2_kvpositions,
		line("cmd arg1 key1 value1 key2 value2 arg2 key4 value4 key3 value3"));
	test_case("kvpos_k21_k34", 0, assert_key1234_2_pos_args, &cmdv2_kvpositions,
		line("cmd arg1 key2 value2 key1 value1 arg2 key3 value3 key4 value4"));
	test_case("kvpos_k3", 0, assert_kv3_in_pos23, &cmdv2_kvpositions,
		line("cmd arg1 key3 value3"));
	test_case("kvpos_k2_k1", -1, assert_not_execd, &cmdv2_kvpositions,
		line("cmd arg1 key2 value2 key1 value1 arg2 key1 value1"));
}

static void test_switches(void)
{
	test_case("kwswitch_none", 0, assert_no_switch_no_pos_args, &cmdv2_switches,
		line("cmd"));
	test_case("kwswitch_1args", 0, assert_no_switch_1_pos_args, &cmdv2_switches,
		line("cmd arg1"));
	test_case("kwswitch_before_12", 0, assert_switch12_1_pos_args, &cmdv2_switches,
		line("cmd -1 -2 value2 arg1"));
	test_case("kwswitch_before_21", 0, assert_switch12_1_pos_args, &cmdv2_switches,
		line("cmd -2 value2 -1 arg1"));
	test_case("kwswitch_after_12", 0, assert_switch12_1_pos_args, &cmdv2_switches,
		line("cmd arg1 -1 -2 value2"));
	test_case("kwswitch_fater_21", 0, assert_switch12_1_pos_args, &cmdv2_switches,
		line("cmd arg1 -2 value2 -1"));
}

static void (*const test_functions[])(void) = {
	test_posargs,
	test_kvargs,
	test_kvpos,
	test_switches,
	NULL
};

int main(void)
{
	return test_run(test_functions);
}
