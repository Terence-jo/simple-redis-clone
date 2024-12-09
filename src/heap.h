#pragma once

#include <cstddef>
#include <cstdint>

struct HeapItem {
  uint64_t val = 0;
  size_t *ref = NULL; // pointer to heap_idx field of an entry
};

void heap_update(HeapItem *a, size_t pos, size_t len);
