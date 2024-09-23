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
