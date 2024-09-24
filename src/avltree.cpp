#include "avltree.h"
#include <cstddef>
#include <cstdint>

// initialise a new tree
void avl_init(AVLNode *node) {
  node->depth = 1;
  node->count = 1;
  node->left = node->right = node->parent =
      NULL; // why? this is done above. I suppose it allows creating a new tree
            // from an existing node.
}

uint32_t avl_depth(AVLNode *node) { return node ? node->depth : 0; }
uint32_t avl_count(AVLNode *node) { return node ? node->count : 0; }

uint32_t max(uint32_t lhs, uint32_t rhs) { return lhs < rhs ? rhs : lhs; }

// maintain depth and count fields
static void avl_update(AVLNode *node) {
  node->depth = 1 + max(avl_depth(node->left), avl_depth(node->right));
  node->count = 1 + avl_count(node->left) + avl_count(node->right);
}

// rotations _must_ return the new node, because they may change the tree root.
static AVLNode *rot_left(AVLNode *node) {
  AVLNode *new_node = node->right;
  if (new_node->left) {
    new_node->left->parent =
        node; // left node of right becomes right node of old subtree root
  }
  node->right = new_node->left;
  new_node->left = node;
  new_node->parent = node->parent;
  node->parent = new_node;
  avl_update(node);
  avl_update(new_node);
  return new_node;
}
static AVLNode *rot_right(AVLNode *node) {
  AVLNode *new_node = node->left;
  if (new_node->right) {
    new_node->right->parent = node;
  }
  node->left = new_node->right;
  new_node->right = node;
  new_node->parent = node->parent;
  node->parent = new_node;
  avl_update(node);
  avl_update(new_node);
  return new_node;
}

// left subtre is too deep:
static AVLNode *avl_fix_left(AVLNode *root) {
  if (avl_depth(root->left->left) < avl_depth(root->left->right)) {
    // right rotation won't rebalance, need to rotate the subtree left
    root->left = rot_left(root->left);
  }
  return rot_right(root);
}
// right subtree is too deep:
static AVLNode *avl_fix_right(AVLNode *root) {
  if (avl_depth(root->right->right) < avl_depth(root->right->left)) {
    root->right = rot_right(root->right);
  }
  return rot_left(root);
}

// from any given node, fix imbalances traversing upwards until the root is
// reached
AVLNode *avl_fix(AVLNode *node) {
  while (true) {
    avl_update(node);
    uint32_t l = avl_depth(node->left);
    uint32_t r = avl_depth(node->right);
    // take the address of the pointer to this node in the parent, so that
    // we can update pointers appropriately after the rotation.
    AVLNode **from = NULL;
    if (AVLNode *parent = node->parent) {
      from = (parent->left == node) ? &parent->left : &parent->right;
    }
    // these return new pointers, so we'll need to maintain the parent's
    // pointer to this node. that's where **from comes in.
    if (l == r + 2) {
      node = avl_fix_left(node);
    } else if (l + 2 == r) {
      node = avl_fix_right(node);
    }
    if (!from) {
      return node;
    }
    // update the parent's pointer to the new rotated node pointer.
    *from = node;
    node = node->parent;
  }
}

// detach a node and return the new root of the whole tree
// note: remember through this that the _in-order_ successor of a node
// is the smallest node in its right subtree.
AVLNode *avl_del(AVLNode *node) {
  if (node->right == NULL) {
    // no right subtree, replace with left subtree
    AVLNode *parent = node->parent;
    if (node->left) {
      node->left->parent = parent;
    }
    // check for parent and attach subtree accordingly
    if (parent) {
      (node == parent->left ? parent->left : parent->right) = node->left;
      return avl_fix(
          parent); // traverses all the way up to the root and returns that
    } else {       // removing root?
      return node->left;
    }
  } else {
    // detach the successor
    AVLNode *victim = node->right; // not yet the successor
    while (victim->left) {
      victim = victim->left;
    } // now we've got the successor
    AVLNode *root = avl_del(victim); // detach successor and get new root
    // swap data
    *victim = *node;
    // maintain the pointers after copying the data
    if (victim->left) {
      victim->left->parent = victim;
    }
    if (victim->right) {
      victim->right->parent = victim;
    }
    if (AVLNode *parent = node->parent) {
      (parent->left == node ? parent->left : parent->right) = victim;
      return root;
    } else { // removing root?
      return victim;
    }
  }
}

AVLNode *avl_offset(AVLNode *node, int64_t offset) {
  int64_t pos = 0;
  while (offset != pos) {
    if (pos < offset && pos + avl_count(node->right) >= offset) {
      // target is inside the right subtree
      node = node->right;
      pos += avl_count(node->left) +
             1; // plus one for the position of the current node
    } else if (pos > offset && pos - avl_count(node->left) <= offset) {
      node = node->left;
      pos -= avl_count(node->right) + 1;
    } else {
      // go to the parent
      AVLNode *parent = node->parent;
      if (!parent) {
        return NULL; // out of range
      }
      if (parent->right == node) {
        pos -= avl_count(node->left) + 1;
      } else {
        pos += avl_count(node->right) + 1;
      }
      node = parent;
    }
  }
  return node;
}
