#pragma once

#include <cstddef>
#include <cstdint>

#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })

// FNV hash. fast but vulnerable. could implement a random prefix or suffix
// to secure on an inter-process basis.
inline uint64_t str_hash(const uint8_t *data, size_t len) {
  // starting h is around 2B. hash is calculated by iteratively
  // adding the next element of data to h and multiplying by
  // a smaller 32-bit int.

  // FNV basis offset, significantly affects overall distribution
  uint32_t h = 0x811C9DC5;
  for (size_t i = 0; i < len; i++) {
    // multiply by FNV prime. it enhances the 'avalanche effect'
    // increasing the chaotic nature of the hash and uniformity
    // of output distribution.
    h = (h + data[i]) * 0x01000193;
  }
  return h;
}

enum {
  SER_NIL = 0, // like NULL
  SER_ERR = 1, // error code and a message
  SER_STR = 2, // string
  SER_INT = 3, // int64
  SER_ARR = 4, // array
  SER_DBL = 5,
};
