#include <cstddef>
/* A doubly-linked list to allow O(1) updating and checking of timers for the
 * event loop. The nearest timer is the only one that matters at any given time,
 * and as soon as it is updated it becomes the most distant, so operations need
 * only consider the front and back of the list.
 */

struct DList {
  DList *prev = NULL;
  DList *next = NULL;
};

inline void dlist_init(DList *node) { node->next = node->prev = node; }

inline bool dlist_empty(DList *node) { return node->next == node; }

inline void dlist_detach(DList *node) {
  node->prev->next = node->next;
  node->next->prev = node->prev;
}

inline void dlist_insert_before(DList *target, DList *rookie) {
  DList *prev = target->prev;
  prev->next = rookie;
  rookie->prev = prev;
  rookie->next = target;
  target->prev = rookie;
}
