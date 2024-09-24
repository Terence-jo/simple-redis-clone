#pragma once

#include "avltree.h"
#include "hashtable.h"

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

ZNode *zset_lookup(ZSet *zset, const char *name, size_t len);
bool zset_add(ZSet *zset, const char *name, size_t len, double score);
ZNode *zset_pop(ZSet *zset, const char *name, size_t len);
void znode_del(ZNode *node);
ZNode *zset_query(ZSet *zset, double score, const char *name, size_t len);
ZNode *znode_offset(ZNode *znode, int64_t offset);
ZNode *zset_pop(ZSet *zset, const char *name, size_t len);
