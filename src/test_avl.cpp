#include "avltree.h"
#include <cassert>
#include <set>

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

// search and delete
static bool del(Container &c, uint32_t val) {
  AVLNode *cur = c.root;
  while (cur) {
    uint32_t node_val = container_of(cur, Data, node)->val;
    if (val == node_val) {
      break;
    }
    cur = val < node_val ? cur->left : cur->right;
  }
  if (!cur) {
    return false; // couldn't find it, no deletion
  }

  c.root = avl_del(cur);
  delete container_of(cur, Data, node);
  return true;
}

static void avl_verify(AVLNode *parent, AVLNode *node) {
  if (!node) {
    return;
  }
  // verify subtrees recursively
  avl_verify(node, node->left);
  avl_verify(node, node->right);
  // 1. Parent pointer is correct
  assert(node->parent == parent);
  // 2. Auxiliary data is correct
  assert(node->count == (1 + avl_count(node->left) + avl_count(node->right)));
  uint32_t l = avl_depth(node->left);
  uint32_t r = avl_depth(node->right);
  assert(node->depth == 1 + max(l, r));
  assert(l == r || l == r + 1 || l + 1 == r);
  // 3. The data is ordered.
  uint32_t val = container_of(node, Data, node)->val;
  if (node->left) {
    assert(node->left->parent == node);
    uint32_t node_val = container_of(node->left, Data, node)->val;
    assert(container_of(node->left, Data, node)->val < val);
  }
  if (node->right) {
    assert(node->right->parent == node);
    assert(container_of(node, Data, node)->val >= val);
  }
}

// compare to reference data structure
static void extract(AVLNode *node, std::multiset<uint32_t> &extracted) {
  if (!node) {
    return;
  }
  extract(node->left, extracted);
  extracted.insert(container_of(node, Data, node)->val);
  extract(node->right, extracted);
}

static void container_verify(Container &c, const std::multiset<uint32_t> &ref) {
  avl_verify(NULL, c.root);
  assert(avl_count(c.root) == ref.size());
  std::multiset<uint32_t> extracted;
  extract(c.root, extracted);
  assert(extracted == ref);
}

int main() {
  Container c = Container();
  std::multiset<uint32_t> ref;

  for (uint32_t i = 0; i < 100; i++) {
    uint32_t val = (uint32_t)rand() % 1000;
    add(c, val);
    ref.insert(val);
    container_verify(c, ref);
  }

  for (uint32_t i = 0; i < 100; i++) {
    uint32_t val = (uint32_t)rand() % 1000;
    while (del(c, val)) {
    }
    ref.erase(val);
    container_verify(c, ref);
  }
}
