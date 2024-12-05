#include <cstddef>
#include <cstdint>

struct HeapItem {
  uint64_t val = 0;
  size_t *ref = NULL; // pointer to heap_idx field of an entry
};

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
  // First we'll grab the value of the Item at pos and hang onto
  // it. Then we want to find its place lower in the heap, so we will
  // iterate down the heap, looking at each child of the current position
  // to see which is smallest, breaking if none are smaller than the item
  // we're pushing down. Whenever the children are smaller we swap the
  // smallest among them into the parent's place and keep moving down. Only
  // once we've broken the loop do we need to worry about putting the original
  // item in the place of the last child we swapped upwards.
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
