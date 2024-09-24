#pragma once

#include <cstddef>
#include <cstdint>

struct AVLNode {
  uint32_t depth = 0;
  uint32_t count =
      0; // size, distinct from depth. this will be used for rank queries.
  AVLNode *left = NULL;  // remember to initialise pointers to NULL
  AVLNode *right = NULL; // to allow existence checks.
  AVLNode *parent = NULL;
};

void avl_init(AVLNode *node);
AVLNode *avl_fix(AVLNode *node);
AVLNode *avl_del(AVLNode *node);
uint32_t avl_count(AVLNode *node);
uint32_t avl_depth(AVLNode *node);
uint32_t max(uint32_t lhs, uint32_t rhs);
AVLNode *avl_offset(AVLNode *node, int64_t offset);
