#include "heap.h"
#include <cstddef>
#include <cstdint>

static size_t heap_parent(size_t i) { return (i + 1) / 2 - 1; }

static size_t heap_left(size_t i) { return i * 2 + 1; }

static size_t heap_right(size_t i) { return i * 2 + 2; }

static void heap_up(HeapItem *a, size_t pos) {
  HeapItem t = a[pos];
  while (pos > 0 && a[heap_parent(pos)].val < t.val) {
    // swap
    a[pos] = a[heap_parent(pos)];
    *a[pos].ref = pos;
    pos = heap_parent(pos);
  }
  a[pos] = t;
  *a[pos].ref = pos;
}

static void heap_down(HeapItem *a, size_t pos, size_t len) {
  HeapItem t = a[pos];
  while (true) {
    size_t l = heap_left(pos);
    size_t r = heap_right(pos);
    size_t min_pos = -1;
    uint64_t min_val = t.val; // always comparing to our diver
    // l and r are unconstrained by the length of the array, need to check
    if (l < len && a[l].val < min_val) {
      min_pos = l;
      min_val = a[l].val;
    }
    if (r < len && a[r].val < min_val) {
      min_pos = r;
      // min_val doesn't help past here in the iteration. no need to update
    }
    if (min_pos == -1) {
      break;
    }
    // swap and update the heap_idx in the containing entry
    a[pos] = a[min_pos];
    *a[pos].ref = pos;
    pos = min_pos;
  }
  a[pos] = t;
  *a[pos].ref = pos;
}

void heap_update(HeapItem *a, size_t pos, size_t len) {
  if (pos > 0 && a[heap_parent(pos)].val > a[pos].val) {
    heap_up(a, pos);
  } else {
    heap_down(a, pos, len);
  }
}
