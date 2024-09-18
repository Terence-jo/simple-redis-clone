#include "avltree.h"
#include "common.h"
#include "hashtable.h"
#include <cstdlib>
#include <cstring>

/*
 * Our sorted set data structure, combining a hashmap primary
 * key with an AVL tree secondary index.
 */

struct ZSet {
  AVLNode *tree = NULL;
  HMap hmap;
};

struct ZNode {
  AVLNode tree; // index by (score, name)
  HNode hmap;   // index by name
  double score = 0;
  size_t len = 0;
  char name[0]; // variable length, reduces allocation overhead
};

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
