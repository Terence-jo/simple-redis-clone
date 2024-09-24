#include "avltree.h"
#include <cassert>

#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })

struct Data {
  AVLNode node;
  uint32_t val = 0;
};

struct Container {
  AVLNode *root = NULL;
};

static void add(Container &c, uint32_t val) {
  Data *data = new Data();
  avl_init(&data->node);
  data->val = val;

  // use the incoming pointer to search for the right node
  AVLNode *cur = NULL;
  AVLNode **from = &c.root;
  while (*from) {
    cur = *from;
    uint32_t node_val = container_of(cur, Data, node)->val;
    from = (val < node_val) ? &cur->left : &cur->right;
  }
  *from = &data->node;
  data->node.parent = cur;
  c.root = avl_fix(
      &data->node); // traverses up to the root, fixing all along the way
}

static void dispose(AVLNode *node) {
  if (node) {
    dispose(node->left);
    dispose(node->right);
    delete container_of(node, Data, node);
  }
}

static void test_case(uint32_t size) {
  // create a tree of given sizenode
  Container c;
  for (uint32_t i = 0; i < size; i++) {
    add(c, i);
  }
  AVLNode *min = c.root;
  while (min->left) {
    min = min->left;
  }

  // for each starting rank
  for (uint32_t i = 0; i < size; i++) {
    AVLNode *node = avl_offset(min, (int64_t)i);
    assert(container_of(node, Data, node)->val == i);
    // test all possible offset
    for (uint32_t j; j < size; j++) {
      int64_t offset = (int64_t)j - (int64_t)i;
      AVLNode *n2 = avl_offset(node, offset);
      assert(container_of(n2, Data, node)->val == j);
    }
    // out of range by one
    assert(!avl_offset(node, -(int64_t)i - 1));
    assert(!avl_offset(node, size - i));
  }
  dispose(c.root);
}

int main() {
  for (uint32_t i = 1; i < 500; i++) {
    test_case(i);
  }
  return 0;
}
