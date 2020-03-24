/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha1.h"
#include "str.h"
#include "mailbox-list-private.h"
#include "dsync-mailbox-tree-private.h"
#include "test-common.h"

#include <stdio.h>

#define MAX_DEPTH 4
#define TEST_NAMESPACE_NAME "INBOX"

static struct mail_namespace inbox_namespace = {
	.prefix = TEST_NAMESPACE_NAME"/",
	.prefix_len = sizeof(TEST_NAMESPACE_NAME)-1 + 1
};

char mail_namespace_get_sep(struct mail_namespace *ns ATTR_UNUSED)
{
	return '/';
}

void mailbox_name_get_sha128(const char *name, guid_128_t guid_128_r)
{
	unsigned char sha[SHA1_RESULTLEN];

	sha1_get_digest(name, strlen(name), sha);
	memcpy(guid_128_r, sha, I_MIN(GUID_128_SIZE, sizeof(sha)));
}

static struct dsync_mailbox_node *
node_create(struct dsync_mailbox_tree *tree, unsigned int counter,
	    const char *name, unsigned int last_renamed_or_created)
{
	struct dsync_mailbox_node *node;

	node = dsync_mailbox_tree_get(tree, name);
	memcpy(node->mailbox_guid, &counter, sizeof(counter));
	node->uid_validity = counter;
	node->existence = DSYNC_MAILBOX_NODE_EXISTS;
	node->last_renamed_or_created = last_renamed_or_created;
	return node;
}

static struct dsync_mailbox_node *
random_node_create(struct dsync_mailbox_tree *tree, unsigned int counter,
		   const char *name)
{
	return node_create(tree, counter, name, i_rand_limit(10));
}

static void nodes_create(struct dsync_mailbox_tree *tree, unsigned int *counter,
			 const char *const *names)
{
	for (; *names != NULL; names++) {
		*counter += 1;
		node_create(tree, *counter, *names, 0);
	}
}

static void nodes_delete(struct dsync_mailbox_tree *tree, unsigned int *counter,
			 const char *const *names)
{
	struct dsync_mailbox_node *node;

	for (; *names != NULL; names++) {
		*counter += 1;
		node = node_create(tree, *counter, *names, 0);
		node->existence = DSYNC_MAILBOX_NODE_DELETED;
	}
}

static void
create_random_nodes(struct dsync_mailbox_tree *tree, const char *parent_name,
		    unsigned int depth, unsigned int *counter)
{
	unsigned int parent_len, i, nodes_count = i_rand_minmax(1, 3);
	string_t *str;

	if (depth == MAX_DEPTH)
		return;

	str = t_str_new(32);
	if (*parent_name != '\0')
		str_printfa(str, "%s/", parent_name);
	parent_len = str_len(str);

	for (i = 0; i < nodes_count; i++) {
		*counter += 1;
		str_truncate(str, parent_len);
		str_printfa(str, "%u.%u", depth, i);
		random_node_create(tree, *counter, str_c(str));
		create_random_nodes(tree, str_c(str), depth+1, counter);
	}
}

static struct dsync_mailbox_tree *create_random_tree(void)
{
	struct dsync_mailbox_tree *tree;
	unsigned int counter = 0;

	tree = dsync_mailbox_tree_init('/', '_');
	create_random_nodes(tree, "", 0, &counter);
	return tree;
}

static void test_tree_nodes_fixup(struct dsync_mailbox_node **pos,
				  unsigned int *newguid_counter)
{
	struct dsync_mailbox_node *node;

	for (node = *pos; node != NULL; node = node->next) {
		if (node->sync_delayed_guid_change) {
			/* the real code will pick one of the GUIDs.
			 we don't really care which one gets picked, so we'll
			 just change them to the same new one */
			memcpy(node->mailbox_guid, newguid_counter,
			       sizeof(*newguid_counter));
			node->uid_validity = *newguid_counter;
			*newguid_counter += 1;
		}
		if (node->existence == DSYNC_MAILBOX_NODE_DELETED)
			node->existence = DSYNC_MAILBOX_NODE_NONEXISTENT;
		test_tree_nodes_fixup(&node->first_child, newguid_counter);
		if (node->existence != DSYNC_MAILBOX_NODE_EXISTS &&
		    node->first_child == NULL) {
			/* nonexistent node, drop it */
			*pos = node->next;
		} else {
			pos = &node->next;
		}
	}
}

static void test_tree_fixup(struct dsync_mailbox_tree *tree)
{
	unsigned int newguid_counter = INT_MAX;

	test_tree_nodes_fixup(&tree->root.first_child, &newguid_counter);
}

static void nodes_dump(const struct dsync_mailbox_node *node, unsigned int depth)
{
	unsigned int i;

	for (; node != NULL; node = node->next) {
		for (i = 0; i < depth; i++) printf(" ");
		printf("%-*s guid:%.5s uidv:%u %d%d %ld\n", 40-depth, node->name,
		       guid_128_to_string(node->mailbox_guid), node->uid_validity,
		       node->existence, node->subscribed ? 1 : 0,
		       (long)node->last_renamed_or_created);
		nodes_dump(node->first_child, depth+1);
	}
}

static void trees_dump(struct dsync_mailbox_tree *tree1,
		       struct dsync_mailbox_tree *tree2)
{
	printf("tree1:\n");
	nodes_dump(tree1->root.first_child, 1);
	printf("tree2:\n");
	nodes_dump(tree2->root.first_child, 1);
}

static void test_trees_nofree(struct dsync_mailbox_tree *tree1,
			      struct dsync_mailbox_tree **_tree2)
{
	struct dsync_mailbox_tree *tree2 = *_tree2;
	struct dsync_mailbox_tree *orig_tree1, *orig_tree2;
	struct dsync_mailbox_tree_sync_ctx *ctx;
	struct dsync_mailbox_node *dup_node1, *dup_node2;

	orig_tree1 = dsync_mailbox_tree_dup(tree1);
	orig_tree2 = dsync_mailbox_tree_dup(tree2);

	/* test tree1 -> tree2 */
	dsync_mailbox_tree_build_guid_hash(tree1, &dup_node1, &dup_node2);
	dsync_mailbox_tree_build_guid_hash(tree2, &dup_node1, &dup_node2);
	ctx = dsync_mailbox_trees_sync_init(tree1, tree2,
					    DSYNC_MAILBOX_TREES_SYNC_TYPE_TWOWAY,
					    DSYNC_MAILBOX_TREES_SYNC_FLAG_DEBUG);
	while (dsync_mailbox_trees_sync_next(ctx) != NULL) {
	}
	dsync_mailbox_trees_sync_deinit(&ctx);
	test_tree_fixup(tree1);
	test_tree_fixup(tree2);
	if (!dsync_mailbox_trees_equal(tree1, tree2)) {
		test_assert(FALSE);
		trees_dump(tree1, tree2);
	}

	/* test tree2 -> tree1 */
	dsync_mailbox_tree_build_guid_hash(orig_tree1, &dup_node1, &dup_node2);
	dsync_mailbox_tree_build_guid_hash(orig_tree2, &dup_node1, &dup_node2);
	ctx = dsync_mailbox_trees_sync_init(orig_tree2, orig_tree1,
					    DSYNC_MAILBOX_TREES_SYNC_TYPE_TWOWAY, 0);
	while (dsync_mailbox_trees_sync_next(ctx) != NULL) {
	}
	dsync_mailbox_trees_sync_deinit(&ctx);
	test_tree_fixup(orig_tree1);
	test_tree_fixup(orig_tree2);
	if (!dsync_mailbox_trees_equal(orig_tree1, orig_tree2)) {
		test_assert(FALSE);
		trees_dump(orig_tree1, orig_tree2);
	}

	/* make sure both directions produced equal trees */
	if (!dsync_mailbox_trees_equal(tree1, orig_tree1)) {
		test_assert(FALSE);
		trees_dump(tree1, orig_tree1);
	}

	dsync_mailbox_tree_deinit(_tree2);
	dsync_mailbox_tree_deinit(&orig_tree1);
	dsync_mailbox_tree_deinit(&orig_tree2);
}

static void
test_tree_nodes_add_namespace(struct dsync_mailbox_node *node,
			      struct mail_namespace *ns)
{
	for (; node != NULL; node = node->next) {
		node->ns = ns;
		test_tree_nodes_add_namespace(node->first_child, ns);
	}
}

static void
test_tree_add_namespace(struct dsync_mailbox_tree *tree,
			struct mail_namespace *ns)
{
	struct dsync_mailbox_node *node, *n;

	node = dsync_mailbox_tree_get(tree, TEST_NAMESPACE_NAME);
	node->existence = DSYNC_MAILBOX_NODE_EXISTS;
	i_assert(tree->root.first_child == node);
	i_assert(node->first_child == NULL);
	node->first_child = node->next;
	for (n = node->first_child; n != NULL; n = n->next)
		n->parent = node;
	node->next = NULL;

	test_tree_nodes_add_namespace(&tree->root, ns);
}

static void test_trees(struct dsync_mailbox_tree *tree1,
		       struct dsync_mailbox_tree *tree2)
{
	struct dsync_mailbox_tree *tree1_dup, *tree2_dup;

	tree1_dup = dsync_mailbox_tree_dup(tree1);
	tree2_dup = dsync_mailbox_tree_dup(tree2);

	/* test without namespace prefix */
	test_trees_nofree(tree1, &tree2);
	dsync_mailbox_tree_deinit(&tree1);

	/* test with namespace prefix */
	test_tree_add_namespace(tree1_dup, &inbox_namespace);
	test_tree_add_namespace(tree2_dup, &inbox_namespace);
	test_trees_nofree(tree1_dup, &tree2_dup);
	dsync_mailbox_tree_deinit(&tree1_dup);
}

static void test_dsync_mailbox_tree_sync_creates(void)
{
	static const char *common_nodes[] = { "foo", "foo/bar", NULL };
	static const char *create1_nodes[] = { "bar", "foo/baz", NULL };
	static const char *create2_nodes[] = { "foo/xyz", "foo/bar/3", NULL };
	struct dsync_mailbox_tree *tree1, *tree2;
	unsigned int counter = 0;

	test_begin("dsync mailbox tree sync creates");
	tree1 = dsync_mailbox_tree_init('/', '_');
	nodes_create(tree1, &counter, common_nodes);
	tree2 = dsync_mailbox_tree_dup(tree1);
	nodes_create(tree1, &counter, create1_nodes);
	nodes_create(tree2, &counter, create2_nodes);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_deletes(void)
{
	static const char *common_nodes[] = { "1", "2", "3", "2/s1", "2/s2", "x/y", NULL };
	static const char *delete1_nodes[] = { "1", "2", NULL };
	static const char *delete2_nodes[] = { "2/s1", "x/y", NULL };
	struct dsync_mailbox_tree *tree1, *tree2;
	unsigned int counter = 0;

	test_begin("dsync mailbox tree sync deletes");
	tree1 = dsync_mailbox_tree_init('/', '_');
	nodes_create(tree1, &counter, common_nodes);
	tree2 = dsync_mailbox_tree_dup(tree1);
	nodes_delete(tree1, &counter, delete1_nodes);
	nodes_delete(tree2, &counter, delete2_nodes);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames1(void)
{
	static const char *common_nodes[] = { "1", "2", "3", "2/s1", "2/s2", "x/y", "3/s3", NULL };
	struct dsync_mailbox_tree *tree1, *tree2;
	struct dsync_mailbox_node *node;
	unsigned int counter = 0;

	test_begin("dsync mailbox tree sync renames 1");
	tree1 = dsync_mailbox_tree_init('/', '_');
	nodes_create(tree1, &counter, common_nodes);
	tree2 = dsync_mailbox_tree_dup(tree1);

	node = dsync_mailbox_tree_get(tree1, "1");
	node->name = "a";
	node->last_renamed_or_created = 1000;
	node = dsync_mailbox_tree_get(tree2, "2");
	node->name = "b";
	node->last_renamed_or_created = 1000;

	node = dsync_mailbox_tree_get(tree1, "3/s3");
	node->name = "z";
	node->last_renamed_or_created = 1000;
	dsync_mailbox_tree_node_detach(node);
	dsync_mailbox_tree_node_attach(node, &tree1->root);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames2(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 2");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1", 1);
	node_create(tree1, 2, "0/1/2", 3);

	node_create(tree2, 1, "0", 0);
	node_create(tree2, 2, "0/1/2", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames3(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 3");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/2", 1);
	node_create(tree1, 2, "0/3", 1);

	node_create(tree2, 1, "0/4/5", 0);
	node_create(tree2, 2, "1", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames4(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 4");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/b", 0);
	node_create(tree1, 2, "c", 2);

	node_create(tree2, 2, "0/a", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames5(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 5");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "b", 0);
	node_create(tree1, 2, "c", 2);

	node_create(tree2, 2, "0/a", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames6(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 6");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1", 0);
	node_create(tree1, 2, "0/2", 1);

	node_create(tree2, 1, "0", 1);
	node_create(tree2, 2, "0/3", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames7(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 7");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/2", 0);
	node_create(tree2, 1, "1/2", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames8(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 8");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1", 0);
	node_create(tree1, 2, "0/2", 1);

	node_create(tree2, 1, "0", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames9(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 9");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1/2", 0);
	node_create(tree1, 2, "0/3", 1);

	node_create(tree2, 1, "0", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames10(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 10");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1", 0);
	node_create(tree1, 3, "0/2/3", 0);

	node_create(tree2, 1, "0", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames11(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 11");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/1", 2);
	node_create(tree1, 0, "0/1/2", 0);

	node_create(tree2, 1, "0", 1);
	node_create(tree2, 0, "0/1/2", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames12(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 12");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/2", 0);
	node_create(tree1, 2, "1", 0);
	node_create(tree1, 3, "1/4", 0);
	node_create(tree1, 4, "1/4/5", 1);

	node_create(tree2, 1, "1", 2);
	node_create(tree2, 2, "1/4", 3);
	node_create(tree2, 3, "1/4/6", 4);
	node_create(tree2, 4, "1/3", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames13(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 13");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 4, "0.0/1.0/2.1", 0);
	node_create(tree1, 5, "0.1", 2);
	node_create(tree1, 6, "0.1/1.0", 2);
	node_create(tree1, 7, "0.1/1.0/2.0", 8);

	node_create(tree2, 5, "0.1/1.0", 5);
	node_create(tree2, 6, "0.1/1.0/2.0", 8);
	node_create(tree2, 7, "0.1/1.1", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames14(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 14");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "1", 0);
	node_create(tree1, 2, "1/2", 0);
	node_create(tree1, 3, "1/2/4", 1);

	node_create(tree2, 1, "1/2", 3);
	node_create(tree2, 2, "1/2/5", 4);
	node_create(tree2, 3, "1/2/4", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames15(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 15");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "1", 0);
	node_create(tree2, 2, "1", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames16(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 16");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "1/2", 4);
	node_create(tree1, 2, "1", 2);

	node_create(tree2, 1, "2", 1);
	node_create(tree2, 2, "1/2", 3);
	node_create(tree2, 3, "1", 5);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames17(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 17");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "1", 1);

	node_create(tree2, 1, "1/2", 0);
	node_create(tree2, 2, "1", 2);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames18(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 18");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 2, "a", 5);
	node_create(tree1, 4, "a/c", 2);
	node_create(tree1, 5, "b", 6);

	node_create(tree2, 1, "a", 7);
	node_create(tree2, 2, "b", 3);
	node_create(tree2, 3, "b/c", 4);
	node_create(tree2, 4, "d", 1);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames19(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 19");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "0/2/1", 1);
	node_create(tree1, 2, "0/4", 3);
	node_create(tree1, 3, "0/2", 2);

	node_create(tree2, 1, "1", 0);
	node_create(tree2, 2, "1/3", 4);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames20(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 20");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "1", 0);
	node_create(tree1, 2, "0", 0);
	node_create(tree1, 3, "0/2", 0);
	/* rename 0 -> 1/0 */
	node_create(tree2, 1, "1", 0);
	node_create(tree2, 2, "1/0", 1);
	node_create(tree2, 3, "1/0/2", 0);

	test_trees_nofree(tree1, &tree2);
	test_assert(tree1->root.first_child != NULL &&
		    tree1->root.first_child->next == NULL);
	dsync_mailbox_tree_deinit(&tree1);
	test_end();
}

static void test_dsync_mailbox_tree_sync_renames21(void)
{
#if 0
	/* FIXME: we can't currently test this without crashing */
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 21");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 1, "INBOX", 0);
	node_create(tree1, 2, "foo", 0);
	/* swap INBOX and foo - the INBOX name is important since it's
	   treated specially */
	node_create(tree2, 1, "foo", 0);
	node_create(tree2, 2, "INBOX", 1);

	test_trees(tree1, tree2);
	test_end();
#endif
}

static void test_dsync_mailbox_tree_sync_renames22(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync renames 22");
	tree1 = dsync_mailbox_tree_init('/', '_');
	tree2 = dsync_mailbox_tree_init('/', '_');

	node_create(tree1, 3, "p/a", 0);
	node_create(tree1, 0, "p/2", 0);
	node_create(tree1, 5, "p/2/h", 0);

	node_create(tree2, 4, "p/1/z", 0);
	node_create(tree2, 1, "p/2", 0);
	node_create(tree2, 2, "p/2/a", 0);
	node_create(tree2, 5, "p/2/y", 0);
	node_create(tree2, 3, "p/3", 0);

	test_trees(tree1, tree2);
	test_end();
}

static void test_dsync_mailbox_tree_sync_random(void)
{
	struct dsync_mailbox_tree *tree1, *tree2;

	test_begin("dsync mailbox tree sync random");
	tree1 = create_random_tree();
	tree2 = create_random_tree();
	test_trees(tree1, tree2);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dsync_mailbox_tree_sync_creates,
		test_dsync_mailbox_tree_sync_deletes,
		test_dsync_mailbox_tree_sync_renames1,
		test_dsync_mailbox_tree_sync_renames2,
		test_dsync_mailbox_tree_sync_renames3,
		test_dsync_mailbox_tree_sync_renames4,
		test_dsync_mailbox_tree_sync_renames5,
		test_dsync_mailbox_tree_sync_renames6,
		test_dsync_mailbox_tree_sync_renames7,
		test_dsync_mailbox_tree_sync_renames8,
		test_dsync_mailbox_tree_sync_renames9,
		test_dsync_mailbox_tree_sync_renames10,
		test_dsync_mailbox_tree_sync_renames11,
		test_dsync_mailbox_tree_sync_renames12,
		test_dsync_mailbox_tree_sync_renames13,
		test_dsync_mailbox_tree_sync_renames14,
		test_dsync_mailbox_tree_sync_renames15,
		test_dsync_mailbox_tree_sync_renames16,
		test_dsync_mailbox_tree_sync_renames17,
		test_dsync_mailbox_tree_sync_renames18,
		test_dsync_mailbox_tree_sync_renames19,
		test_dsync_mailbox_tree_sync_renames20,
		test_dsync_mailbox_tree_sync_renames21,
		test_dsync_mailbox_tree_sync_renames22,
		test_dsync_mailbox_tree_sync_random,
		NULL
	};
	return test_run(test_functions);
}
