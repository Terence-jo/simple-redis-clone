#include "hashtable.h"
#include <cassert>
#include <cstddef>

/*==================================================
 *          Basic Functionality
==================================================*/
// n must be a power of 2
static void h_init(HTable *htab, size_t n) {
  // remembering that powers of 2 have the bitwise form of 10...0, (n - 1) & n
  // will always be zero for powers of 2 as the subtraction cascades down the
  // bits, inverting each of them.
  assert(n > 0 && ((n - 1) & n) == 0);
  htab->tab =
      (HNode **)calloc(n, sizeof(HNode *)); // calloc() allocates n blocks of
                                            // foo size and initialises to zero
  htab->mask = n - 1; // bit mask to use in place of modulo
  htab->size = 0;
}

// this insertion doesn't care about the keys or values, it's
// just dealing with the structure.
static void h_insert(HTable *htab, HNode *node) {
  size_t pos = node->hcode & htab->mask; // slot index
  HNode *next =
      htab->tab[pos]; // this will be a null pointer if there is nothing there
  node->next = next;  // prepend to the list
  htab->tab[pos] = node;
  htab->size++;
}

// `eq` is a callback function passed in for comparing keys.
// the address of the incoming pointer is returned, rather than the
// node pointer, to facilitate deletions.
static HNode **h_lookup(HTable *htab, HNode *key,
                        bool (*eq)(HNode *, HNode *)) {
  if (!htab->tab) {
    return NULL;
  }

  size_t pos = key->hcode & htab->mask;
  HNode **from = &htab->tab[pos]; // address of result pointer
  // iterate through contents of `tab[pos]` looking for `key`
  for (HNode *cur; (cur = *from) != NULL; from = &cur->next) {
    // hcode fast fail path comes in here
    if (cur->hcode == key->hcode && eq(cur, key)) {
      return from;
    }
  }
  return NULL;
}

// receive the address of an incoming pointer to a node gained from
// h_lookup and detach that node from the HTable, returning the
// pointer.
static HNode *h_detach(HTable *htab, HNode **from) {
  HNode *node = *from; // de-reference the address to get a pointer to an HNode
  *from = node->next;  // the pointer at *from now points to the next node.
  htab->size--;
  return node; // we're returning the node, so we don't even need to clean up
               // here.
}

void h_scan(HTable *tab, void (*f)(HNode *, void *), void *arg) {
  if (tab->size == 0) {
    return;
  }
  for (size_t i = 0; i < tab->mask + 1; i++) {
    HNode *node = tab->tab[i];
    while (node) {
      f(node, arg);
      node = node->next;
    }
  }
}

/*==================================================
 *    Progressive resizing and the real interface
==================================================*/
const size_t k_max_load_factor = 8; // load factor being keys/nslots
const size_t k_resizing_work = 128; // constant resizing work

static void hm_help_resizing(HMap *hmap) {
  size_t nwork = 0;
  while (nwork <= k_resizing_work && hmap->htab2.size > 0) {
    // if the current slot is empty, move to the next slot
    HNode **from = &hmap->htab2.tab[hmap->resizing_pos];
    if (!*from) {
      hmap->resizing_pos++;
      continue;
    }
    h_insert(&hmap->htab1, h_detach(&hmap->htab2, from));
    nwork++;
  }

  // if the resizing is done then we need to clean up htab2
  if (hmap->htab2.size == 0 && hmap->htab2.tab) {
    free(hmap->htab2.tab);
    hmap->htab2 = HTable();
  }
}

static void hm_start_resizing(HMap *hmap) {
  assert(hmap->htab2.tab == NULL);
  hmap->htab2 = hmap->htab1;
  h_init(&hmap->htab1, (hmap->htab1.mask + 1) * 2);
  hmap->resizing_pos = 0;
}

// insertion to this table will insert, check load factor, potentially
// begin resizing, and do some resizing work if necessary.
void hm_insert(HMap *hmap, HNode *node) {
  if (!hmap->htab1.tab) {
    h_init(&hmap->htab1, 4);
  }
  h_insert(&hmap->htab1, node);

  // check the load factor. if htab2's table exists we're already resizing
  if (!hmap->htab2.tab) {
    size_t load_factor = hmap->htab1.size / (hmap->htab1.mask + 1);
    if (load_factor >= k_max_load_factor) {
      hm_start_resizing(hmap); // begin resizing, creating htab2
    }
  }
  hm_help_resizing(hmap); // no work done if htab2 has size 0
}

// search both tables in lookup
HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
  hm_help_resizing(hmap);
  HNode **from = h_lookup(&hmap->htab1, key, eq);
  // h_lookup returns NULL if not found
  from = from ? from : h_lookup(&hmap->htab2, key, eq);
  if (!from) {
    return NULL;
  }
  return *from;
}

HNode *hm_pop(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
  hm_help_resizing(hmap);
  if (HNode **from = h_lookup(&hmap->htab1, key, eq)) {
    return h_detach(&hmap->htab1, from);
  }
  if (HNode **from = h_lookup(&hmap->htab2, key, eq)) {
    return h_detach(&hmap->htab2, from);
  }
  return NULL;
}

size_t hm_size(HMap *hmap) { return hmap->htab1.size + hmap->htab2.size; }

void hm_destroy(HMap *hmap) {
  free(hmap->htab1.tab);
  free(hmap->htab2.tab);
  *hmap = HMap();
}
