#ifndef DRIVER_TEST_H
#define DRIVER_TEST_H 1

struct test_driver_result_set {
	size_t rows, cols, cur;
	const char *const *col_names;
	const char ***row_data;
};

struct test_driver_result {
	/* expected queries */
	size_t nqueries;
	size_t cur;
	unsigned int affected_rows;
	const char *const *queries;

	/* test result, rows and columns */
	struct test_driver_result_set *result;
};

void sql_driver_test_register(void);
void sql_driver_test_unregister(void);

void sql_driver_test_add_expected_result(struct sql_db *_db,
					 const struct test_driver_result *result);
void sql_driver_test_clear_expected_results(struct sql_db *_db);

#endif
