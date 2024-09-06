#pragma once

#include <cstddef>
#include <cstdint>

// Hash code is cached in the node for two reasons,
// it can help to reuse keys when resizing, and it
// provides a fast path for checking equality.
struct HNode {
  HNode *next;
  uint64_t hcode = 0; // cached hash value
};

// Fixed size hash table to be gradually resized.
struct HTable {
  HNode **tab = NULL; // the list of node pointers
  size_t mask = 0;    // 2^n - 1
  size_t size = 0;
};

// the real interface we'll use will have two fixed-size tables for progressive
// resizing.
struct HMap {
  struct HTable htab1; // the newer table
  struct HTable htab2; // the older table, used while resizing.
  uint32_t resizing_pos;
};

void hm_insert(HMap *hmap, HNode *node);
HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
HNode *hm_pop(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
size_t hm_size(HMap *hmap);
void hm_destroy(HMap *hmap);
