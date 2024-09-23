#include "zset.h"
#include "avltree.h"
#include "common.h"
#include "hashtable.h"
#include <cstdlib>
#include <cstring>

/*
 * Our sorted set data structure, combining a hashmap primary
 * key with an AVL tree secondary index.
 */

struct HKey {
  HNode node;
  const char *name = NULL;
  size_t len = 0;
};

static bool hcmp(HNode *node, HNode *key) {
  ZNode *znode = container_of(node, ZNode, hmap);
  HKey *hkey = container_of(key, HKey, node);
  if (znode->len != hkey->len) {
    return false;
  }
  return 0 == memcmp(znode->name, hkey->name, znode->len);
}

// construct a new ZNode with name of length `len` and a score
static ZNode *znode_new(const char *name, size_t len, double score) {
  ZNode *node = (ZNode *)malloc(sizeof(ZNode) + len);
  avl_init(&node->tree);
  node->hmap.next = NULL;
  node->hmap.hcode = str_hash((uint8_t *)name, len);
  node->score = score;
  node->len = len;
  memcpy(&node->name[0], name, len);
  return node;
}

// ZNode lookup. It's just a hashtable lookup
ZNode *zset_lookup(ZSet *zset, const char *name, size_t len) {
  if (!zset->tree) {
    return NULL;
  }
  // Use HKey helper to refer ease comparisons
  HKey key;
  key.node.hcode = str_hash((uint8_t *)name, len);
  key.name = name;
  key.len = len;
  HNode *found = hm_lookup(&zset->hmap, &key.node, &hcmp);
  return found ? container_of(found, ZNode, hmap) : NULL;
}

static uint32_t min(size_t lhs, size_t rhs) { return lhs < rhs ? lhs : rhs; }

static bool zless(AVLNode *lhs, double score, const char *name, size_t len) {
  ZNode *zl = container_of(lhs, ZNode, tree);
  if (zl->score != score) {
    return zl->score < score;
  }
  int rv = memcmp(zl->name, name, min(zl->len, len));
  if (rv != 0) {
    return rv < 0;
  }
  return zl->len < len;
}
// zless is overloaded to compute two different stages of the
// same operation. not sure quite how much I agree with this.
static bool zless(AVLNode *lhs, AVLNode *rhs) {
  ZNode *zr = container_of(rhs, ZNode, tree);
  return zless(lhs, zr->score, zr->name, zr->len);
}

// insert into the AVL tree of a ZNode
static void tree_add(ZSet *zset, ZNode *node) {
  AVLNode *cur = NULL;          // current node
  AVLNode **from = &zset->tree; // incoming pointer to the next node
  while (*from) {
    cur = *from;
    // traverse depending on comparison with node to insert
    from = zless(&node->tree, cur) ? &cur->left : &cur->right;
  }
  *from = &node->tree; // attach new node
  node->tree.parent = cur;
  zset->tree =
      avl_fix(&node->tree); // start from the inserted node, traverse up
}

// think about how this will need to work. detach and re-insert the node
// to handle order.
static void zset_update(ZSet *zset, ZNode *node, double score) {
  if (node->score == score) {
    return;
  }
  zset->tree = avl_del(&node->tree);
  node->score = score;
  avl_init(&node->tree);
  tree_add(zset, node);
}

bool zset_add(ZSet *zset, const char *name, size_t len, double score) {
  ZNode *node = zset_lookup(zset, name, len);
  if (node) {
    zset_update(zset, node, score);
    return false;
  } else {
    node = znode_new(name, len, score);
    hm_insert(&zset->hmap, &node->hmap);
    tree_add(zset, node);
    return true;
  }
}

static ZNode *zset_pop(ZSet *zset, const char *name, size_t len) {
  ZNode *node = zset_lookup(zset, name, len);
  if (!node) {
    return NULL;
  }
  zset->tree = avl_del(&node->tree);
  (void)hm_pop(&zset->hmap, &node->hmap, &hcmp);
  return node;
}

// zset_add allocates the node, so zset_del will need to deallocate the
// node in the same module.
void znode_del(ZNode *node) { free(node); }
