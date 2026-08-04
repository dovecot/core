/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "test-common.h"

#include "json-pointer.h"
#include "json-tree-query.h"

/*
 * Build the example tree from RFC 6901 sect 5:
 *   {
 *      "foo": ["bar", "baz"],
 *      "":    0,
 *      "a/b": 1,
 *      "c%d": 2,
 *      "e^f": 3,
 *      "g|h": 4,
 *      "i\\j": 5,
 *      "k\"l": 6,
 *      " ":   7,
 *      "m~n": 8
 *   }
 */
static struct json_tree *
make_rfc6901_tree(struct json_tree_node **root_r)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *foo;

	jtree = json_tree_create_object(&root);
	*root_r = root;

	foo = json_tree_node_add_array(root, "foo");
	json_tree_node_add_string(foo, NULL, "bar");
	json_tree_node_add_string(foo, NULL, "baz");

	json_tree_node_add_number_int(root, "", 0);
	json_tree_node_add_number_int(root, "a/b", 1);
	json_tree_node_add_number_int(root, "c%d", 2);
	json_tree_node_add_number_int(root, "e^f", 3);
	json_tree_node_add_number_int(root, "g|h", 4);
	json_tree_node_add_number_int(root, "i\\j", 5);
	json_tree_node_add_number_int(root, "k\"l", 6);
	json_tree_node_add_number_int(root, " ", 7);
	json_tree_node_add_number_int(root, "m~n", 8);

	return jtree;
}

static void test_assert_int_value(const struct json_tree_node *node,
				  intmax_t expected)
{
	intmax_t v = 0;
	test_assert(node != NULL);
	if (node == NULL)
		return;
	test_assert(json_tree_node_is_number(node));
	test_assert(json_tree_node_get_intmax(node, &v) == 0);
	test_assert_cmp(v, ==, expected);
}

static void test_rfc6901_examples_json_string(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root;
	const struct json_tree_node *node;

	jtree = make_rfc6901_tree(&root);

	test_begin("rfc6901 examples (json-string form)");

	/* "" -> whole document (root) */
	node = json_tree_node_resolve_pointer(root, "");
	test_assert(node == root);

	/* "/foo" -> array ["bar","baz"] */
	node = json_tree_node_resolve_pointer(root, "/foo");
	test_assert(node != NULL);
	test_assert(json_tree_node_is_array(node));

	/* "/foo/0" -> "bar" */
	node = json_tree_node_resolve_pointer(root, "/foo/0");
	test_assert(node != NULL);
	test_assert(json_tree_node_is_string(node));
	test_assert_strcmp(json_tree_node_get_str(node), "bar");

	/* "/" -> 0 (empty member name) */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/"), 0);

	/* "/a~1b" -> 1 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/a~1b"), 1);

	/* "/c%d" -> 2 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/c%d"), 2);

	/* "/e^f" -> 3 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/e^f"), 3);

	/* "/g|h" -> 4 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/g|h"), 4);

	/* "/i\\j" -> 5 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/i\\j"), 5);

	/* "/k\"l" -> 6 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/k\"l"), 6);

	/* "/ " -> 7 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/ "), 7);

	/* "/m~0n" -> 8 */
	test_assert_int_value(json_tree_node_resolve_pointer(root, "/m~0n"), 8);

	test_end();
	json_tree_unref(&jtree);
}

static void test_rfc6901_examples_uri_fragment(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root;
	const struct json_tree_node *node;
	struct json_pointer *path;
	const char *error;

	test_begin("rfc6901 examples (uri-fragment form)");

	jtree = make_rfc6901_tree(&root);

	/* "#" -> whole document */
	test_assert(json_pointer_create_uri_fragment("#", &path, &error) == 0);
	node = json_tree_node_pointer_query(path, root);
	test_assert(node == root);
	json_pointer_free(&path);

	/* "#/foo" -> array */
	test_assert(json_pointer_create_uri_fragment("#/foo", &path, &error) == 0);
	node = json_tree_node_pointer_query(path, root);
	test_assert(node != NULL);
	test_assert(json_tree_node_is_array(node));
	json_pointer_free(&path);

	/* "#/foo/0" -> "bar" */
	test_assert(json_pointer_create_uri_fragment("#/foo/0",
						  &path, &error) == 0);
	node = json_tree_node_pointer_query(path, root);
	test_assert(node != NULL);
	test_assert_strcmp(json_tree_node_get_str(node), "bar");
	json_pointer_free(&path);

	/* "#/" -> 0 */
	test_assert(json_pointer_create_uri_fragment("#/", &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 0);
	json_pointer_free(&path);

	/* "#/a~1b" -> 1 */
	test_assert(json_pointer_create_uri_fragment("#/a~1b",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 1);
	json_pointer_free(&path);

	/* "#/c%25d" -> 2 */
	test_assert(json_pointer_create_uri_fragment("#/c%25d",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 2);
	json_pointer_free(&path);

	/* "#/e%5Ef" -> 3 */
	test_assert(json_pointer_create_uri_fragment("#/e%5Ef",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 3);
	json_pointer_free(&path);

	/* "#/g%7Ch" -> 4 */
	test_assert(json_pointer_create_uri_fragment("#/g%7Ch",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 4);
	json_pointer_free(&path);

	/* "#/i%5Cj" -> 5 */
	test_assert(json_pointer_create_uri_fragment("#/i%5Cj",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 5);
	json_pointer_free(&path);

	/* "#/k%22l" -> 6 */
	test_assert(json_pointer_create_uri_fragment("#/k%22l",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 6);
	json_pointer_free(&path);

	/* "#/%20" -> 7 */
	test_assert(json_pointer_create_uri_fragment("#/%20",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 7);
	json_pointer_free(&path);

	/* "#/m~0n" -> 8 */
	test_assert(json_pointer_create_uri_fragment("#/m~0n",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 8);
	json_pointer_free(&path);

	/* Lowercase hex digits in percent-escapes must decode the same as
	   uppercase. "#/e%5Ef" above used uppercase "5E"; verify "#/e%5ef"
	   (lower-case) resolves to the same "e^f" member. Likewise "%5C"
	   vs "%5c" for "i\\j". */
	test_assert(json_pointer_create_uri_fragment("#/e%5ef",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 3);
	json_pointer_free(&path);

	test_assert(json_pointer_create_uri_fragment("#/i%5cj",
						  &path, &error) == 0);
	test_assert_int_value(json_tree_node_pointer_query(path, root), 5);
	json_pointer_free(&path);
	json_tree_unref(&jtree);

	test_end();
}

static void test_decode_order(void)
{
	/* RFC 6901 sect 4: "~1" must be decoded before "~0".
	   So "~01" -> "~1" (literal), not "/". */
	struct json_tree *jtree;
	struct json_tree_node *root;
	const struct json_tree_node *node;

	jtree = json_tree_create_object(&root);
	json_tree_node_add_number_int(root, "~1", 42);

	test_begin("rfc6901 escape decode order");
	node = json_tree_node_resolve_pointer(root, "/~01");
	test_assert_int_value(node, 42);
	test_end();

	json_tree_unref(&jtree);
}

static void test_parse_errors(void)
{
	struct json_pointer *path;
	const char *error;

	test_begin("rfc6901 parser errors");

	/* Missing leading '/' on non-empty pointer */
	test_assert(json_pointer_create("foo", &path, &error) < 0);
	test_assert(error != NULL);

	/* Trailing '~' */
	test_assert(json_pointer_create("/foo~", &path, &error) < 0);

	/* '~' followed by something other than '0' or '1' */
	test_assert(json_pointer_create("/~2", &path, &error) < 0);
	test_assert(json_pointer_create("/foo/~x", &path, &error) < 0);

	/* Lone '~' token */
	test_assert(json_pointer_create("/~", &path, &error) < 0);

	test_end();
}

static void test_array_indices(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *arr;
	const struct json_tree_node *node;

	jtree = json_tree_create_object(&root);
	arr = json_tree_node_add_array(root, "arr");
	json_tree_node_add_string(arr, NULL, "zero");
	json_tree_node_add_string(arr, NULL, "one");
	json_tree_node_add_string(arr, NULL, "two");

	test_begin("rfc6901 array indices");

	/* Valid: 0, 1, 2 */
	node = json_tree_node_resolve_pointer(root, "/arr/0");
	test_assert(node != NULL);
	test_assert_strcmp(json_tree_node_get_str(node), "zero");
	node = json_tree_node_resolve_pointer(root, "/arr/1");
	test_assert_strcmp(json_tree_node_get_str(node), "one");
	node = json_tree_node_resolve_pointer(root, "/arr/2");
	test_assert_strcmp(json_tree_node_get_str(node), "two");

	/* Out of bounds */
	test_assert(json_tree_node_resolve_pointer(root, "/arr/3") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/arr/99") == NULL);

	/* Past-end token "-" -> NULL (RFC: nonexistent member after last) */
	test_assert(json_tree_node_resolve_pointer(root, "/arr/-") == NULL);

	/* Leading-zero indices are invalid -> NULL */
	test_assert(json_tree_node_resolve_pointer(root, "/arr/00") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/arr/01") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/arr/000") == NULL);

	/* Non-digit index -> NULL */
	test_assert(json_tree_node_resolve_pointer(root, "/arr/x") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/arr/1x") == NULL);

	/* Overflow -> NULL */
	test_assert(json_tree_node_resolve_pointer(root, "/arr/4294967296") == NULL);

	test_end();
	json_tree_unref(&jtree);
}

static void test_descend_into_scalar(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root;

	jtree = json_tree_create_object(&root);
	json_tree_node_add_string(root, "s", "hello");
	json_tree_node_add_number_int(root, "n", 3);
	json_tree_node_add_true(root, "t");
	json_tree_node_add_null(root, "z");

	test_begin("rfc6901 cannot descend into scalar");
	test_assert(json_tree_node_resolve_pointer(root, "/s/x") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/s/0") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/n/foo") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/t/a") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/z/a") == NULL);
	test_end();

	json_tree_unref(&jtree);
}

static void test_member_lookup_in_array(void)
{
	/* A non-index token applied to an array returns NULL. */
	struct json_tree *jtree;
	struct json_tree_node *root, *arr;

	jtree = json_tree_create_object(&root);
	arr = json_tree_node_add_array(root, "arr");
	json_tree_node_add_string(arr, NULL, "zero");

	test_begin("rfc6901 non-index token on array");
	test_assert(json_tree_node_resolve_pointer(root, "/arr/foo") == NULL);
	test_end();
	json_tree_unref(&jtree);
}

static void test_empty_tree(void)
{
	struct json_tree *jtree;

	test_begin("rfc6901 empty tree");
	jtree = json_tree_create();
	test_assert(json_tree_resolve_pointer(jtree, "") == NULL);
	test_assert(json_tree_resolve_pointer(jtree, "/foo") == NULL);
	json_tree_unref(&jtree);
	test_end();
}

static void test_subnode_relative(void)
{
	/* Pointer evaluated relative to the given start node, not the
	   document root. Pinned API contract. */
	struct json_tree *jtree;
	struct json_tree_node *root, *obj, *deep;
	const struct json_tree_node *node;

	jtree = json_tree_create_object(&root);
	obj = json_tree_node_add_object(root, "obj");
	deep = json_tree_node_add_object(obj, "deep");
	json_tree_node_add_string(deep, "leaf", "value");

	test_begin("rfc6901 pointer relative to sub-node");
	node = json_tree_node_resolve_pointer(obj, "/deep/leaf");
	test_assert(node != NULL);
	test_assert_strcmp(json_tree_node_get_str(node), "value");

	/* Empty pointer against sub-node returns that sub-node. */
	test_assert(json_tree_node_resolve_pointer(obj, "") == obj);
	test_end();
	json_tree_unref(&jtree);
}

static void test_compile_and_reuse(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *arr, *item0, *item1;
	const struct json_tree_node *node;
	struct json_pointer *path;
	const char *error;

	jtree = json_tree_create_object(&root);
	arr = json_tree_node_add_array(root, "items");
	item0 = json_tree_node_add_object(arr, NULL);
	json_tree_node_add_string(item0, "name", "alice");
	item1 = json_tree_node_add_object(arr, NULL);
	json_tree_node_add_string(item1, "name", "bob");

	test_begin("rfc6901 compile once, execute many");
	test_assert(json_pointer_create("/name", &path, &error) == 0);

	node = json_tree_node_pointer_query(path, item0);
	test_assert(node != NULL);
	test_assert_strcmp(json_tree_node_get_str(node), "alice");

	node = json_tree_node_pointer_query(path, item1);
	test_assert(node != NULL);
	test_assert_strcmp(json_tree_node_get_str(node), "bob");
	json_pointer_free(&path);
	test_assert(path == NULL);
	test_end();

	json_tree_unref(&jtree);
}

static void test_uri_fragment_errors(void)
{
	struct json_pointer *path;
	const char *error;

	test_begin("rfc6901 uri-fragment parser errors");

	/* Missing leading '#' */
	test_assert(json_pointer_create_uri_fragment("foo", &path, &error) < 0);
	test_assert(error != NULL);
	test_assert(json_pointer_create_uri_fragment("/foo", &path, &error) < 0);

	/* Bad percent encoding */
	test_assert(json_pointer_create_uri_fragment("#/%", &path, &error) < 0);
	test_assert(json_pointer_create_uri_fragment("#/%2", &path, &error) < 0);
	test_assert(json_pointer_create_uri_fragment("#/%ZZ", &path, &error) < 0);
	test_assert(json_pointer_create_uri_fragment("#/%2G", &path, &error) < 0);

	/* Empty fragment is fine: "#" == whole document */
	test_assert(json_pointer_create_uri_fragment("#", &path, &error) == 0);
	json_pointer_free(&path);

	test_end();
}

/* Build the canonical bookstore example from RFC 9535 sect 1.5 so that we can
   exercise RFC 6901 pointers against the same tree of test data that the
   JSONPath spec uses for its examples.  RFC 9535 syntax (`$.store.book[*]`,
   `$..author`, slices, filters) is intentionally out of scope here - only
   the singular-node queries that fit RFC 6901's grammar are covered. */
static struct json_tree *
make_rfc9535_bookstore(struct json_tree_node **root_r)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *store, *book, *b, *bicycle;

	jtree = json_tree_create_object(&root);
	*root_r = root;

	store = json_tree_node_add_object(root, "store");
	book = json_tree_node_add_array(store, "book");

	b = json_tree_node_add_object(book, NULL);
	json_tree_node_add_string(b, "category", "reference");
	json_tree_node_add_string(b, "author", "Nigel Rees");
	json_tree_node_add_string(b, "title", "Sayings of the Century");
	json_tree_node_add_number_str(b, "price", "8.95");

	b = json_tree_node_add_object(book, NULL);
	json_tree_node_add_string(b, "category", "fiction");
	json_tree_node_add_string(b, "author", "Evelyn Waugh");
	json_tree_node_add_string(b, "title", "Sword of Honour");
	json_tree_node_add_number_str(b, "price", "12.99");

	b = json_tree_node_add_object(book, NULL);
	json_tree_node_add_string(b, "category", "fiction");
	json_tree_node_add_string(b, "author", "Herman Melville");
	json_tree_node_add_string(b, "title", "Moby Dick");
	json_tree_node_add_string(b, "isbn", "0-553-21311-3");
	json_tree_node_add_number_str(b, "price", "8.99");

	b = json_tree_node_add_object(book, NULL);
	json_tree_node_add_string(b, "category", "fiction");
	json_tree_node_add_string(b, "author", "J. R. R. Tolkien");
	json_tree_node_add_string(b, "title", "The Lord of the Rings");
	json_tree_node_add_string(b, "isbn", "0-395-19395-8");
	json_tree_node_add_number_str(b, "price", "22.99");

	bicycle = json_tree_node_add_object(store, "bicycle");
	json_tree_node_add_string(bicycle, "color", "red");
	json_tree_node_add_number_int(bicycle, "price", 399);

	return jtree;
}

static void assert_str_value(const struct json_tree_node *node,
			     const char *expected)
{
	test_assert(node != NULL);
	if (node == NULL)
		return;
	test_assert(json_tree_node_is_string(node));
	test_assert_strcmp(json_tree_node_get_str(node), expected);
}

static void assert_number_str(const struct json_tree_node *node,
			      const char *expected)
{
	test_assert(node != NULL);
	if (node == NULL)
		return;
	test_assert(json_tree_node_is_number(node));
	test_assert_strcmp(json_tree_node_as_str(node), expected);
}

static void test_rfc9535_bookstore(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root;
	const struct json_tree_node *node;

	jtree = make_rfc9535_bookstore(&root);

	test_begin("rfc9535 bookstore example via rfc6901 pointers");

	/* Whole document. */
	test_assert(json_tree_node_resolve_pointer(root, "") == root);

	/* Container nodes. */
	node = json_tree_node_resolve_pointer(root, "/store");
	test_assert(node != NULL && json_tree_node_is_object(node));

	node = json_tree_node_resolve_pointer(root, "/store/book");
	test_assert(node != NULL && json_tree_node_is_array(node));

	node = json_tree_node_resolve_pointer(root, "/store/bicycle");
	test_assert(node != NULL && json_tree_node_is_object(node));

	/* Singular queries that overlap RFC 9535 examples. */

	/* JSONPath $..book[2] -> /store/book/2 */
	node = json_tree_node_resolve_pointer(root, "/store/book/2");
	test_assert(node != NULL && json_tree_node_is_object(node));

	/* $..book[2].author -> "Herman Melville" */
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/2/author"), "Herman Melville");

	/* $..book[2].publisher -> empty result (missing member) */
	test_assert(json_tree_node_resolve_pointer(root,
			"/store/book/2/publisher") == NULL);

	/* First book's fields. */
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/0/category"), "reference");
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/0/author"), "Nigel Rees");
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/0/title"), "Sayings of the Century");
	assert_number_str(json_tree_node_resolve_pointer(root,
			 "/store/book/0/price"), "8.95");

	/* ISBN only present on books 2 and 3. */
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/2/isbn"), "0-553-21311-3");
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/3/isbn"), "0-395-19395-8");
	test_assert(json_tree_node_resolve_pointer(root,
			"/store/book/0/isbn") == NULL);
	test_assert(json_tree_node_resolve_pointer(root,
			"/store/book/1/isbn") == NULL);

	/* Last book title. */
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/book/3/title"), "The Lord of the Rings");

	/* Bicycle. */
	assert_str_value(json_tree_node_resolve_pointer(root,
			 "/store/bicycle/color"), "red");
	test_assert_int_value(json_tree_node_resolve_pointer(root,
			 "/store/bicycle/price"), 399);

	/* Past-end and out-of-range on book array. */
	test_assert(json_tree_node_resolve_pointer(root, "/store/book/-") == NULL);
	test_assert(json_tree_node_resolve_pointer(root, "/store/book/4") == NULL);

	test_end();
	json_tree_unref(&jtree);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_rfc6901_examples_json_string,
		test_rfc6901_examples_uri_fragment,
		test_decode_order,
		test_parse_errors,
		test_array_indices,
		test_descend_into_scalar,
		test_member_lookup_in_array,
		test_empty_tree,
		test_subnode_relative,
		test_compile_and_reuse,
		test_uri_fragment_errors,
		test_rfc9535_bookstore,
		NULL
	};

	return test_run(test_functions);
}
