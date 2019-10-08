/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "istream.h"

#include "json-tree.h"

struct json_tree_node_list {
	struct json_tree_node *head, *tail;
	unsigned int count;
};

struct json_tree_node {
	struct json_tree *tree;
	struct json_tree_node *parent, *prev, *next;

	struct json_node node;
};

struct json_tree {
	struct json_tree_node node;

	pool_t pool;
	int refcount;

	ARRAY_TYPE(json_tree) subtrees;
	ARRAY(struct istream *) istreams;
};

/*
 * Tree object
 */

struct json_tree *json_tree_create_pool(pool_t pool)
{
	struct json_tree *jtree;

	pool_ref(pool);

	jtree = p_new(pool, struct json_tree, 1);
	jtree->refcount = 1;
	jtree->pool = pool;

	jtree->node.tree = jtree;
	jtree->node.node.type = JSON_TYPE_NONE;
	jtree->node.node.value.content_type = JSON_CONTENT_TYPE_NONE;

	return jtree;
}

struct json_tree *json_tree_create(void)
{
	struct json_tree *jtree;
	pool_t pool;

	pool = pool_alloconly_create("json tree", 1024);
	jtree = json_tree_create_pool(pool);
	pool_unref(&pool);

	return jtree;
}

void json_tree_ref(struct json_tree *jtree)
{
	i_assert(jtree->refcount > 0);
	jtree->refcount++;
}

void json_tree_unref(struct json_tree **_jtree)
{
	struct json_tree *jtree = *_jtree;

	if (jtree == NULL)
		return;
	*_jtree = NULL;

	i_assert(jtree->refcount > 0);
	if (--jtree->refcount > 0)
		return;

	if (array_is_created(&jtree->subtrees)) {
		struct json_tree **subtree_idx;
		array_foreach_modifiable(&jtree->subtrees, subtree_idx)
			json_tree_unref(subtree_idx);
		array_free(&jtree->subtrees);
	}
	if (array_is_created(&jtree->istreams)) {
		struct istream **istream_idx;
		array_foreach_modifiable(&jtree->istreams, istream_idx)
			i_stream_unref(istream_idx);
		array_free(&jtree->istreams);
	}
	pool_unref(&jtree->pool);
}

bool json_tree_is_object(const struct json_tree *jtree)
{
	return json_node_is_object(&jtree->node.node);
}

bool json_tree_is_array(const struct json_tree *jtree)
{
	return json_node_is_array(&jtree->node.node);
}

bool json_tree_is_string(const struct json_tree *jtree)
{
	return json_node_is_string(&jtree->node.node);
}

bool json_tree_is_number(const struct json_tree *jtree)
{
	return json_node_is_number(&jtree->node.node);
}

bool json_tree_is_true(const struct json_tree *jtree)
{
	return json_node_is_true(&jtree->node.node);
}

bool json_tree_is_false(const struct json_tree *jtree)
{
	return json_node_is_false(&jtree->node.node);
}

bool json_tree_is_boolean(const struct json_tree *jtree)
{
	return json_node_is_boolean(&jtree->node.node);
}

bool json_tree_is_null(const struct json_tree *jtree)
{
	return json_node_is_null(&jtree->node.node);
}

/*
 * Tree node
 */

static inline struct json_tree_node_list *
json_tree_node_create_list(struct json_tree_node *jtnode)
{
	i_assert(jtnode->node.type == JSON_TYPE_OBJECT ||
		jtnode->node.type == JSON_TYPE_ARRAY);
	i_assert(jtnode->node.value.content_type == JSON_CONTENT_TYPE_LIST);
	if (jtnode->node.value.content.list == NULL) {
		jtnode->node.value.content.list =
			p_new(jtnode->tree->pool,
			      struct json_tree_node_list, 1);
	}
	return jtnode->node.value.content.list;
}

struct json_tree_node *json_tree_get_root(struct json_tree *jtree)
{
	return &jtree->node;
}

const struct json_tree_node *
json_tree_get_root_const(const struct json_tree *jtree)
{
	return &jtree->node;
}

static struct json_tree_node *
json_tree_node_create(struct json_tree_node *parent, const char *name)
{
	struct json_tree *jtree = parent->tree;
	struct json_tree_node_list *list;
	struct json_tree_node *jtnode;

	i_assert(name != NULL || parent->node.type != JSON_TYPE_OBJECT);

	if (parent == &jtree->node && parent->node.type == JSON_TYPE_NONE) {
		/* We're substituting the root (name is ignored) */
		i_assert(parent->node.value.content_type ==
			 JSON_CONTENT_TYPE_NONE);
		jtnode = &jtree->node;
		i_zero(jtnode);
	} else {
		/* We're creating a new node */
		jtnode = p_new(jtree->pool, struct json_tree_node, 1);
		jtnode->node.name = (name == NULL ?
				     NULL : p_strdup(jtree->pool, name));
		jtnode->parent = parent;
		list = json_tree_node_create_list(parent);
		DLLIST2_APPEND(&list->head, &list->tail, jtnode);
		list->count++;
	}

	jtnode->tree = jtree;
	return jtnode;
}

/* node */

struct json_tree_node *
json_tree_node_add(struct json_tree_node *parent,
		   const struct json_node *jnode)
{
	return json_tree_node_add_value(parent, jnode->name, jnode->type,
					&jnode->value);
}

/* object, array */

struct json_tree_node *
json_tree_node_add_object(struct json_tree_node *parent, const char *name)
{
	struct json_tree_node *jtnode;

	jtnode = json_tree_node_create(parent, name);
	jtnode->node.type = JSON_TYPE_OBJECT;
	jtnode->node.value.content_type = JSON_CONTENT_TYPE_LIST;
	jtnode->node.value.content.list = NULL;

	return jtnode;
}

struct json_tree_node *
json_tree_node_add_array(struct json_tree_node *parent, const char *name)
{
	struct json_tree_node *jtnode;

	jtnode = json_tree_node_create(parent, name);
	jtnode->node.type = JSON_TYPE_ARRAY;
	jtnode->node.value.content_type = JSON_CONTENT_TYPE_LIST;
	jtnode->node.value.content.list = NULL;

	return jtnode;
}

/* value */

struct json_tree_node *
json_tree_node_add_value(struct json_tree_node *parent, const char *name,
			 enum json_type type, const struct json_value *jvalue)
{
	struct json_tree *jtree = parent->tree;
	struct json_tree_node *jtnode;
	struct json_data *jdata;
	unsigned char *data;

	jtnode = json_tree_node_create(parent, name);
	jtnode->node.type = type;
	jtnode->node.value = *jvalue;
	switch (jvalue->content_type) {
	case JSON_CONTENT_TYPE_NONE:
		break;
	case JSON_CONTENT_TYPE_LIST:
		/* Equivalent to calling json_tree_node_add_array() or
		   json_tree_node_add_object(); doesn't copy list */
		jtnode->node.value.content.list = NULL;
		break;
	case JSON_CONTENT_TYPE_STRING:
		jtnode->node.value.content.str =
			p_strdup(jtree->pool, jvalue->content.str);
		break;
	case JSON_CONTENT_TYPE_DATA:
		jdata = p_new(jtree->pool, struct json_data, 1);
		*jdata = *jvalue->content.data;
		data = p_malloc(jtree->pool, jdata->size + 1);
		jdata->data = memcpy(data, jdata->data, jdata->size);
		jtnode->node.value.content.data = jdata;
		break;
	case JSON_CONTENT_TYPE_STREAM:
		if (!array_is_created(&jtree->istreams))
			i_array_init(&jtree->istreams, 4);
		array_append(&jtree->istreams, &jvalue->content.stream, 1);
		i_stream_ref(jvalue->content.stream);
		break;
	case JSON_CONTENT_TYPE_INTEGER:
		break;
	case JSON_CONTENT_TYPE_TREE:
		i_assert(jvalue->content.tree != jtree);
		if (!array_is_created(&jtree->subtrees))
			i_array_init(&jtree->subtrees, 4);
		array_append(&jtree->subtrees, &jvalue->content.tree, 1);
		json_tree_ref(jvalue->content.tree);
		break;
	}

	return jtnode;
}

/* string */

struct json_tree_node *
json_tree_node_add_string(struct json_tree_node *parent, const char *name,
			  const char *str)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = str;
	return json_tree_node_add_value(parent, name, JSON_TYPE_STRING,
					&jvalue);
}

struct json_tree_node *
json_tree_node_add_data(struct json_tree_node *parent, const char *name,
			const unsigned char *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&data);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;
	return json_tree_node_add_value(parent, name, JSON_TYPE_STRING,
					&jvalue);
}

struct json_tree_node *
json_tree_node_add_string_stream(struct json_tree_node *parent,
				 const char *name, struct istream *input)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STREAM;
	jvalue.content.stream = input;
	return json_tree_node_add_value(parent, name, JSON_TYPE_STRING,
					&jvalue);
}

/* number */

struct json_tree_node *
json_tree_node_add_number_int(struct json_tree_node *parent, const char *name,
			      uintmax_t num)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_INTEGER;
	jvalue.content.intnum = num;
	return json_tree_node_add_value(parent, name, JSON_TYPE_NUMBER,
					&jvalue);
}

struct json_tree_node *
json_tree_node_add_number_str(struct json_tree_node *parent, const char *name,
			      const char *num)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = num;
	return json_tree_node_add_value(parent, name, JSON_TYPE_NUMBER,
					&jvalue);
}

/* false, true */

struct json_tree_node *
json_tree_node_add_false(struct json_tree_node *parent, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_tree_node_add_value(parent, name, JSON_TYPE_FALSE,
					&jvalue);
}

struct json_tree_node *
json_tree_node_add_true(struct json_tree_node *parent, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_tree_node_add_value(parent, name, JSON_TYPE_TRUE,
					&jvalue);
}

struct json_tree_node *
json_tree_node_add_boolean(struct json_tree_node *parent, const char *name,
			   bool val)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_tree_node_add_value(
		parent, name, (val ? JSON_TYPE_TRUE : JSON_TYPE_FALSE),
		&jvalue);
}

/* null */

struct json_tree_node *
json_tree_node_add_null(struct json_tree_node *parent, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_tree_node_add_value(parent, name, JSON_TYPE_NULL,
					&jvalue);
}

/* JSON-text */

struct json_tree_node *
json_tree_node_add_text(struct json_tree_node *parent, const char *name,
			const char *literal)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = literal;
	return json_tree_node_add_value(parent, name, JSON_TYPE_TEXT, &jvalue);
}

struct json_tree_node *
json_tree_node_add_text_data(struct json_tree_node *parent, const char *name,
			     const unsigned char *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&jdata);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;
	return json_tree_node_add_value(parent, name, JSON_TYPE_TEXT, &jvalue);
}

struct json_tree_node *
json_tree_node_add_subtree(struct json_tree_node *parent, const char *name,
			   struct json_tree *tree)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_TREE;
	jvalue.content.tree = tree;
	return json_tree_node_add_value(parent, name, JSON_TYPE_TEXT, &jvalue);
}

/*
 * Tree inspection
 */

enum json_type json_tree_node_get_type(const struct json_tree_node *jtnode)
{
	return jtnode->node.type;
}

const char *json_tree_node_get_name(const struct json_tree_node *jtnode)
{
	return jtnode->node.name;
}

struct json_tree *
json_tree_node_get_tree(struct json_tree_node *jtnode)
{
	return jtnode->tree;
}

const struct json_tree *
json_tree_node_get_tree_const(const struct json_tree_node *jtnode)
{
	return jtnode->tree;
}

bool json_tree_node_is_root(const struct json_tree_node *jtnode)
{
	return (json_tree_get_root(jtnode->tree) == jtnode);
}

bool json_tree_node_is_object(const struct json_tree_node *jtnode)
{
	return json_node_is_object(&jtnode->node);
}

bool json_tree_node_is_array(const struct json_tree_node *jtnode)
{
	return json_node_is_array(&jtnode->node);
}

bool json_tree_node_is_string(const struct json_tree_node *jtnode)
{
	return json_node_is_string(&jtnode->node);
}

bool json_tree_node_is_number(const struct json_tree_node *jtnode)
{
	return json_node_is_number(&jtnode->node);
}

bool json_tree_node_is_true(const struct json_tree_node *jtnode)
{
	return json_node_is_true(&jtnode->node);
}

bool json_tree_node_is_false(const struct json_tree_node *jtnode)
{
	return json_node_is_false(&jtnode->node);
}

bool json_tree_node_is_boolean(const struct json_tree_node *jtnode)
{
	return json_node_is_boolean(&jtnode->node);
}

bool json_tree_node_is_null(const struct json_tree_node *jtnode)
{
	return json_node_is_null(&jtnode->node);
}

const struct json_node *
json_tree_node_get(const struct json_tree_node *jtnode)
{
	return &jtnode->node;
}

struct json_tree_node *
json_tree_node_get_next(const struct json_tree_node *jtnode)
{
	return jtnode->next;
}

struct json_tree_node *
json_tree_node_get_parent(const struct json_tree_node *jtnode)
{
	return jtnode->parent;
}

struct json_tree_node *
json_tree_node_get_child(const struct json_tree_node *jtnode)
{
	i_assert(jtnode->node.value.content_type == JSON_CONTENT_TYPE_LIST);
	if (jtnode->node.value.content.list == NULL)
		return NULL;
	return jtnode->node.value.content.list->head;
}

unsigned int
json_tree_node_get_child_count(const struct json_tree_node *jtnode)
{
	i_assert(jtnode->node.value.content_type == JSON_CONTENT_TYPE_LIST);
	if (jtnode->node.value.content.list == NULL)
		return 0;
	return jtnode->node.value.content.list->count;
}

struct json_tree_node *
json_tree_node_get_member(const struct json_tree_node *jtnode,
			  const char *name)
{
	struct json_tree_node *child;

	i_assert(json_node_is_object(&jtnode->node));
	i_assert(jtnode->node.value.content_type == JSON_CONTENT_TYPE_LIST);

	if (jtnode->node.value.content.list == NULL)
		return NULL;

	child = jtnode->node.value.content.list->head;
	while (child != NULL) {
		if (strcmp(child->node.name, name) == 0)
			return child;
		child = child->next;
	}
	return NULL;
}

struct json_tree_node *
json_tree_node_get_child_with(const struct json_tree_node *jtnode,
			      const char *key, const char *value)
{
	struct json_tree_node *child;

	i_assert(jtnode->node.value.content_type == JSON_CONTENT_TYPE_LIST);
	if (jtnode->node.value.content.list == NULL)
		return NULL;

	child = jtnode->node.value.content.list->head;
	while (child != NULL) {
		struct json_tree_node *member;

		if (!json_node_is_object(&child->node))
			continue;
		member = json_tree_node_get_member(child, key);
		if (member == NULL)
			continue;
		if (!json_tree_node_is_string(member))
			continue;
		if (strcmp(json_tree_node_get_str(member), value) == 0)
			break;

		child = child->next;
	}

	return child;
}

/*
 * Walker
 */

struct json_tree_walker {
	const struct json_tree_node *root, *node;
	ARRAY_TYPE(json_tree_node_const) sub_nodes;
	unsigned int node_level;

	bool node_is_end:1;
};

struct json_tree_walker *
json_tree_walker_create_from_node(const struct json_tree_node *tree_node)
{
	struct json_tree_walker *twalker;

	i_assert(tree_node != NULL);

	twalker = i_new(struct json_tree_walker, 1);
	twalker->root = tree_node;

	return twalker;
}

struct json_tree_walker *
json_tree_walker_create(const struct json_tree *tree)
{
	i_assert(tree != NULL);
	return json_tree_walker_create_from_node(
		json_tree_get_root_const(tree));
}

void json_tree_walker_free(struct json_tree_walker **_twalker)
{
	struct json_tree_walker *twalker = *_twalker;

	if (twalker == NULL)
		return;
	*_twalker = NULL;

	array_free(&twalker->sub_nodes);
	i_free(twalker);
}

static const struct json_tree_node *
json_tree_walk_next(struct json_tree_walker *twalker, bool *is_end_r)
{
	const struct json_tree_node *tnode = twalker->node, *tnode_next;

	*is_end_r = FALSE;

	if (tnode == NULL) {
		i_assert(twalker->node_level == 0);
		twalker->node_level++;
		return twalker->root;
	}

	bool tnode_is_end = twalker->node_is_end;
	const struct json_node *node = &tnode->node;

	if (!json_node_is_singular(node) && !tnode_is_end) {
		tnode_next = json_tree_node_get_child(tnode);
		if (tnode_next != NULL) {
			twalker->node_level++;
			return tnode_next;
		}
		*is_end_r = TRUE;
		return tnode;
	}

	tnode_next = json_tree_node_get_next(tnode);
	if (tnode_next != NULL || twalker->node_level == 0)
		return tnode_next;

	twalker->node_level--;
	*is_end_r = TRUE;
	return json_tree_node_get_parent(tnode);
}

bool json_tree_walk(struct json_tree_walker *twalker, struct json_node *node_r)
{
	const struct json_tree_node *tnode_next;
	bool tnode_next_is_end;

	tnode_next = json_tree_walk_next(twalker, &tnode_next_is_end);
	if (tnode_next == NULL) {
		i_assert(twalker->node_level == 0);
		i_zero(node_r);
		twalker->node = twalker->root = NULL;
		twalker->node_is_end = TRUE;
		return FALSE;
	}
	if (json_tree_node_is_root(tnode_next) && twalker->node_level > 1) {
		const struct json_tree_node *tnode_sub = tnode_next;

		/* Returned to root of subtree */
		i_assert(tnode_next_is_end);
		i_assert(array_is_created(&twalker->sub_nodes));
		i_assert(array_count(&twalker->sub_nodes) > 0);
		tnode_next = *array_back(&twalker->sub_nodes);
		array_pop_back(&twalker->sub_nodes);

		i_zero(node_r);
		node_r->name = tnode_next->node.name;
		node_r->type = tnode_sub->node.type;

		twalker->node = tnode_next;
		twalker->node_is_end = TRUE;
		return TRUE;
	}

	const struct json_node *node_next = &tnode_next->node;

	if (tnode_next_is_end) {
		i_zero(node_r);
		node_r->name = node_next->name;
		node_r->type = node_next->type;
	} else if (node_next->type == JSON_TYPE_TEXT &&
		   node_next->value.content_type == JSON_CONTENT_TYPE_TREE) {
		struct json_tree *tree = node_next->value.content.tree;
		const struct json_tree_node *tnode_sub;

		/* Descend into subtree */
		if (!array_is_created(&twalker->sub_nodes))
			i_array_init(&twalker->sub_nodes, 4);
		array_push_back(&twalker->sub_nodes, &tnode_next);
		tnode_sub = json_tree_get_root(tree);
		i_assert(tnode_sub != NULL);
		i_assert(tnode_sub->node.type != JSON_TYPE_NONE);
		*node_r = tnode_sub->node;
		node_r->name = node_next->name;
		tnode_next = tnode_sub;
	} else {
		*node_r = tnode_next->node;
	}

	twalker->node = tnode_next;
	twalker->node_is_end = tnode_next_is_end;
	return TRUE;
}
