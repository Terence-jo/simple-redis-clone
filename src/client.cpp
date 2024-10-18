#include "common.h"
#include <arpa/inet.h>
#include <assert.h>
#include <cstdint>
#include <cstdio>
#include <errno.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

/*
 * A simple TCP client. `read_full` and `write_full` are just helper
 * wrappers around the `read()` and `write()` syscalls to handle the
 * return of fewer bytes than requested. Query handles the wrapping and
 * writing of requests to the socket, and the reading and printing of
 * responses from the server.
 */

const uint32_t k_max_msg = 4096;

static void die(const char *msg) {
  int err = errno;
  fprintf(stderr, "[%d] %s\n", err, msg);
  abort();
}

static void msg(const char *msg) { fprintf(stderr, "%s\n", msg); }

static int32_t read_full(int fd, char *buf, size_t n) {
  while (n > 0) {
    // read() returns whatever data is available in the kernel, it may
    // not be the whole request.
    ssize_t rv = read(fd, buf, n);
    if (rv <= 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    n -= (size_t)rv;
    // Increment pointer to capture more data from read() if
    // necessary.
    buf += rv;
  }
  return 0;
}

static int32_t write_all(int fd, const char *buf, size_t n) {
  while (n > 0) {
    // same as write, may only write partial data if the kernel
    // buffer is full.
    ssize_t rv = write(fd, buf, n);
    if (rv <= 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    n -= (size_t)rv;
    buf += rv;
  }
  return 0;
}

static int32_t add_message_header(char *wbuf,
                                  const std::vector<std::string> &cmd,
                                  uint32_t *len) {
  for (const std::string &s : cmd) {
    *len += 4 + s.size();
  }
  if (*len > k_max_msg) {
    return -1;
  }
  memcpy(wbuf, len, 4); // assume little-endian
  return 0;
}

static void fill_with_cmd(char *wbuf, size_t pos,
                          const std::vector<std::string> &cmd) {
  for (const std::string &s : cmd) {
    uint32_t sz = (uint32_t)s.size();
    memcpy(&wbuf[pos], &sz, 4);
    memcpy(&wbuf[pos + 4], s.data(), s.size());
    pos += 4 + s.size();
  }
}

// client code for making requests and receiving responses with our
// new msg_len|msg outer protocol, and nstr|len|str_1|...|len|str_n
// inner protocol
static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
  uint32_t len = 4; // the message will at least have the number of strings
  char wbuf[4 + k_max_msg];
  if (0 != add_message_header(wbuf, cmd, &len)) {
    return -1;
  }
  uint32_t size_with_header = 4 + len;

  uint32_t n = cmd.size();
  memcpy(&wbuf[4], &n, 4);
  size_t pos = 8;
  fill_with_cmd(wbuf, pos, cmd);
  return write_all(fd, wbuf, size_with_header);
}

static int32_t on_response(const uint8_t *data, size_t size) {
  if (size < 1) {
    msg("bad response");
    return -1;
  }
  switch (data[0]) {
  case SER_NIL:
    printf("(nil)\n");
    return 1;
  case SER_ERR:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      int32_t code = 0;
      int32_t len = 0;
      memcpy(&code, &data[1], 4);
      memcpy(&len, &data[1 + 4], 4);
      if (size < 1 + 8 + len) {
        msg("bad response");
        return -1;
      }
      printf("(err) %d %.*s\n", code, len, &data[1 + 8]);
      return 1 + 8 + len;
    }
  case SER_STR:
    if (size < 1 + 4) {
      msg("bad response");
      return -1;
    }
    {
      uint32_t len = 0;
      memcpy(&len, &data[1], 4);
      if (size < 1 + 4 + len) {
        msg("bad response");
        return -1;
      }
      printf("(str) %.*s\n", len, &data[1 + 4]);
      return 1 + 4 + len;
    }
  case SER_INT:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      int64_t val = 0;
      memcpy(&val, &data[1], 8);
      printf("(int) %lld\n", val);
      return 1 + 8;
    }
  case SER_ARR:
    if (size < 1 + 4) {
      msg("bad response");
      return -1;
    }
    {
      uint32_t len = 0;
      memcpy(&len, &data[1], 4);
      printf("(arr) len=%u\n", len);
      size_t arr_pos = 1 + 4;
      for (uint32_t i = 0; i < len; i++) {
        // with the recursion for arrays, it doesn't matter how nested the data
        // may be.
        int32_t rv = on_response(&data[arr_pos], size - arr_pos);
        if (rv < 0) {
          return rv;
        }
        arr_pos += rv;
      }
      printf("(arr) end\n");
      return ((int32_t)arr_pos);
    }
  case SER_DBL:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      double val = 0;
      memcpy(&val, &data[1], 8);
      printf("(dbl) %f\n", val);
      return 1 + 8;
    }
  default:
    msg("bad response");
    return -1;
  }
}

static int32_t read_res(int fd) {
  // parse a response, beginning with the 4-byte header
  char rbuf[4 + k_max_msg + 1];
  errno = 0;
  int32_t err = read_full(fd, rbuf, 4);
  if (err) {
    if (errno == 0) {
      msg("EOF");
    } else {
      msg("read() error");
    }
    return -1;
  }

  uint32_t len;
  memcpy(&len, rbuf, 4);
  if (len > k_max_msg) {
    msg("too long");
    return -1;
  }

  // parse reply body
  err = read_full(fd, &rbuf[4], len);
  if (err) {
    msg("read() error");
    return -1;
  }

  // do something
  int32_t rv = on_response((uint8_t *)&rbuf[4], len);
  if (rv > 0 && (uint32_t)rv != len) {
    msg("bad response");
    rv = -1;
  }
  return rv;
}

int main(int argc, char **argv) {
  // Write something, read back, then close connection to the server.
  // First make another TCP socket
  int fd = socket(PF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    die("socket()");
  }

  // Instantiate the target address
  struct sockaddr_in addr = {};
  addr.sin_family = PF_INET;
  addr.sin_port = ntohs(1234);
  addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK); // 127.0.0.1
  int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
  if (rv) {
    die("connect()");
  }

  std::vector<std::string> cmd;
  for (int i = 1; i < argc; i++) {
    cmd.push_back(argv[i]);
  }
  int32_t err = send_req(fd, cmd);
  if (err) {
    goto L_DONE;
  }
  err = read_res(fd);
  if (err) {
    goto L_DONE;
  }

L_DONE:
  close(fd);
  return 0;
}
