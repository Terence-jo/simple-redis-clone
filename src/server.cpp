#include "common.h"
#include "hashtable.h"
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/event.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

/*
 * A simple TCP server running in an event loop. Note: this server is
 * employing pipelining, looping trough each possible request in a full
 * read buffer before the next read. A number of operations within the
 * pipelining loop may return false, breaking the loop and waiting for "the next
 * iteration". This is specifically the next iteration of the event loop, after
 * connections have been polled again. Read buffer contents for each connection
 * will persist until the buffer can be filled, processed, and cleared. This
 * happens most often with EAGAIN signals.
 */

const size_t k_max_msg = 4096;

enum {
  STATE_REQ = 0,
  STATE_RES = 1,
  STATE_END = 2, // mark the connection for deletion
};

enum {
  ERR_UNKNOWN = 0,
  ERR_2BIG = 1,
};

// placeholder data structure for the key space
static std::map<std::string, std::string> g_map;

struct Conn {
  int fd = -1;
  uint32_t state = 0; // either STATE_REQ or STATE_RES
  // buffer for reading
  size_t rbuf_contents_size = 0;
  size_t rbuf_consumed = 0;
  uint8_t rbuf[4 + k_max_msg];
  // buffer for writing
  size_t wbuf_contents_size = 0;
  size_t wbuf_sent = 0;
  uint8_t wbuf[4 + k_max_msg];
  // cache for a response that could not be written
  // to the buffer
  std::string resp_cache;
};

// Print error and exit. A C idiom.
static void die(const char *msg) {
  int err = errno;
  fprintf(stderr, "[%d] %s\n", err, msg);
  abort();
}

static void msg(const char *msg) { fprintf(stderr, "%s\n", msg); }

// set a socket to read and write in non-blocking mode
static void fd_set_nb(int fd) {
  errno = 0;
  int flags = fcntl(fd, F_GETFL, 0);
  if (errno) {
    die("fcntl error");
    return;
  }

  // OR update assignment. Clever bitfield stuff
  flags |= O_NONBLOCK;

  errno = 0;
  (void)fcntl(fd, F_SETFL, flags);
  if (errno) {
    die("fcntl error");
  }
}

static void conn_put(std::vector<Conn *> &fd2conn, struct Conn *conn) {
  // this takes advantage of the fact that `fd`s are assigned from 0
  // incrementing by 1 each time. the fd value is the number of fds.
  if (fd2conn.size() <= (size_t)conn->fd) {
    fd2conn.resize(conn->fd + 1);
  }
  fd2conn[conn->fd] = conn;
}

static int32_t accept_new_conn(std::vector<Conn *> &fd2conn, int serverfd) {
  struct sockaddr_in client_addr = {};
  socklen_t addrlen = sizeof(client_addr);
  int connfd = accept(serverfd, (struct sockaddr *)&client_addr, &addrlen);
  if (connfd < 0) {
    msg("accept() error");
    return -1;
  }

  // set up connection
  fd_set_nb(connfd);
  // need to heap-allocate the connection since it will outlive this function
  // and we're passing its pointer around.
  struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));
  if (!conn) {
    close(connfd);
    return -1;
  }
  conn->fd = connfd;
  conn->state = STATE_REQ;
  conn->rbuf_contents_size = 0;
  conn->rbuf_consumed = 0;
  conn->wbuf_contents_size = 0;
  conn->wbuf_sent = 0;
  conn_put(fd2conn, conn);
  return 0;
}

static bool try_one_request(Conn *conn);
static void state_res(Conn *conn);
static void state_req(Conn *conn);

static bool try_fill_buffer(Conn *conn) {
  // this is why the `rbuf_contents_size` field is important,
  // we need to track the buffer contents relative to
  // its capacity.
  assert(conn->rbuf_contents_size <= sizeof(conn->rbuf));

  size_t remain = conn->rbuf_contents_size - conn->rbuf_consumed;
  if (remain && conn->rbuf_consumed > 0) {
    memmove(conn->rbuf, &conn->rbuf[conn->rbuf_consumed], remain);
    conn->rbuf_consumed = 0;
  }
  if (conn->wbuf_contents_size == 0) {
    conn->rbuf_consumed = 0;
  }
  conn->rbuf_contents_size = remain;

  ssize_t rv = 0;
  do {
    size_t cap = sizeof(conn->rbuf) - conn->rbuf_contents_size;
    // read into the buffer after the last filled element
    rv = read(conn->fd, &conn->rbuf[conn->rbuf_contents_size], cap);
  } while (rv < 0 &&
           errno ==
               EINTR); // EINTR means interrupted by a signal, need to retry
  if (rv < 0 && errno == EAGAIN) {
    // got EAGAIN, we're blocked. stop for now
    return false;
  }
  if (rv < 0) {
    msg("read() error");
    conn->state = STATE_END;
    return false;
  }
  if (rv == 0) { // 0 bytes read, EOF
    if (conn->rbuf_contents_size > 0) {
      msg("unexpected EOF");
    } else {
      msg("EOF");
    }
    conn->state = STATE_END;
    return false;
  }

  conn->rbuf_contents_size += (size_t)rv;
  assert(conn->rbuf_contents_size <= sizeof(conn->rbuf));

  // try to process requests one by one
  // loop is for pipelining
  while (try_one_request(conn)) {
  }
  return (conn->state == STATE_REQ);
}

const uint32_t k_max_args = 1024;

static int32_t parse_req(const unsigned char *req, uint32_t reqlen,
                         std::vector<std::string> &out) {
  // make sure we've at least got our length header, this time telling us
  // how many strings we've got. then read the header, and start
  // iterating through the buffer, decrementing our num strings value
  // until we've added all the strings to `out`
  if (reqlen < 4) {
    return -1;
  }

  uint32_t n = 0;
  memcpy(&n, req, 4);
  if (n > k_max_args) {
    return -1;
  }

  size_t pos = 4;
  while (n--) { // nifty syntax, when n hits zero this will become false
    // make sure we've got the string length header
    if (pos + 4 > reqlen) {
      return -1;
    }
    // parse strings like before: read length header, read data
    size_t sz = 0;
    memcpy(&sz, &req[pos], 4);
    pos += 4;
    if (pos + sz > reqlen) {
      return -1;
    }
    // cast as char array and construct a string by passing length
    out.push_back(std::string((char *)&req[pos], sz));
    pos += sz;
  }

  if (pos != reqlen) {
    // trailing garbage after n strings
    return -1;
  }
  return 0;
}

static bool cmd_is(const std::string &cmd, const char *cmd_wanted) {
  return 0 == strcasecmp(cmd.c_str(), cmd_wanted);
}

/*==================================================
Hashtable functionality
==================================================*/
// the global key space
static struct {
  HMap db;
} g_data;

struct Entry {
  struct HNode node;
  std::string key;
  std::string val;
};

static bool entry_eq(HNode *lhs, HNode *rhs) {
  struct Entry *le = container_of(lhs, struct Entry, node);
  struct Entry *re = container_of(rhs, struct Entry, node);
  return le->key == re->key; // just a string equality
}

static void out_nil(std::string &out) { out.push_back(SER_NIL); }
static void out_str(std::string &out, const std::string &val) {
  out.push_back(SER_STR);
  uint32_t len = (uint32_t)val.size();
  out.append((char *)&len, 4);
  out.append(val);
}
static void out_int(std::string &out, int64_t val) {
  out.push_back(SER_INT);
  out.append((char *)&val, 8);
}
static void out_err(std::string &out, int32_t code, const std::string &msg) {
  out.push_back(SER_ERR);
  out.append((char *)&code, 4);
  uint32_t len = msg.size();
  out.append((char *)&len, 4);
  out.append(msg);
}
// array just puts the length in first, without packing elements
static void out_arr(std::string &out, uint32_t n) {
  out.push_back(SER_ARR);
  out.append((char *)&n, 4);
}

static void cb_scan(HNode *node, void *arg) {
  std::string &out = *(std::string *)arg;
  out_str(out, container_of(node, Entry, node)->key);
}

static void do_keys(std::vector<std::string> &cmd, std::string &out) {
  (void)cmd;
  out_arr(out, (uint32_t)hm_size(&g_data.db));
  h_scan(&g_data.db.htab1, &cb_scan, &out);
  h_scan(&g_data.db.htab2, &cb_scan, &out);
}

static void do_get(std::vector<std::string> &cmd, std::string &out) {
  // Create a key to find, fill it from the command and set its hash
  Entry target;
  target.key.swap(cmd[1]);
  target.node.hcode =
      str_hash((unsigned char *)target.key.data(), target.key.size());

  HNode *node = hm_lookup(&g_data.db, &target.node, &entry_eq);
  if (!node) {
    out_nil(out);
    return;
  }
  const std::string &val = container_of(node, struct Entry, node)->val;
  assert(val.size() < k_max_msg);
  out_str(out, val);
  return;
}

// allocate an Entry (didn't need to do that above since `target` is only used
// in the get), set the hash code, key, and value, then add it to g_data with
// hm_insert
static void do_set(std::vector<std::string> &cmd, std::string &out) {
  // create a lookup target on the stack, only heap allocate if necessary,
  // provide a fast path.
  Entry target;
  target.key.swap(cmd[1]);
  target.node.hcode =
      str_hash((unsigned char *)target.key.data(), target.key.size());
  HNode *node = hm_lookup(&g_data.db, &target.node, &entry_eq);
  if (node) {
    container_of(node, Entry, node)->val.swap(cmd[2]);
    out_nil(out);
    return;
  }

  // slow path
  Entry *entry = new Entry;
  entry->key.swap(target.key);
  entry->val.swap(cmd[2]);
  entry->node.hcode = target.node.hcode;
  hm_insert(&g_data.db, &entry->node);
  out_nil(out);
  return;
}

// create a target entry, pop its node from the hmap, get its container and
// deallocate its resources.
static void do_del(const std::vector<std::string> &cmd, std::string &out) {
  Entry target;
  target.key = cmd[1];
  target.node.hcode =
      str_hash((unsigned char *)target.key.data(), target.key.size());

  HNode *node = hm_pop(&g_data.db, &target.node, &entry_eq);
  if (node) {
    delete container_of(node, Entry, node);
  }
  out_int(out, node ? 1 : 0);
  return;
}

static void do_request(std::vector<std::string> &cmd, std::string &out) {
  if (cmd.size() == 1 && cmd_is(cmd[0], "keys")) {
    do_keys(cmd, out);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
    do_get(cmd, out);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
    do_set(cmd, out);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
    do_del(cmd, out);
  } else {
    out_err(out, ERR_UNKNOWN, "Unknown cmd");
  }
}

static bool try_one_request(Conn *conn) {
  if (conn->resp_cache.size() > 0) {
    uint32_t cachelen = (uint32_t)conn->resp_cache.size();
    memcpy(conn->wbuf, &cachelen, 4);
    memcpy(&conn->wbuf[4], conn->resp_cache.data(), cachelen);
    conn->resp_cache.clear();
  }
  size_t unread = conn->rbuf_contents_size - conn->rbuf_consumed;
  // try to parse a request from the buffer
  if (unread < 4) {
    // incomplete request, wait for next read
    return false;
  }
  uint32_t len = 0;
  memcpy(&len, &conn->rbuf[conn->rbuf_consumed], 4);
  if (len > k_max_msg) {
    msg("too long");
    conn->state = STATE_END;
    return false;
  }
  if (4 + len > unread) {
    // incomplete message, retry next iteration
    return false;
  }

  // parse request
  std::vector<std::string> cmd;
  if (0 != parse_req(&conn->rbuf[4], len, cmd)) {
    msg("bad request");
    conn->state = STATE_END;
    return false;
  }

  // got a request, generate a response
  std::string out;
  do_request(cmd, out);
  if (4 + out.size() > k_max_msg) {
    out.clear();
    out_err(out, ERR_2BIG, "response is too big");
  }

  // pack response into the buffer
  size_t wbuf_msg_start = conn->wbuf_contents_size + 4;
  size_t next_size = wbuf_msg_start + out.size();
  if (next_size <= sizeof(conn->wbuf)) {
    uint32_t wlen = (uint32_t)out.size();
    memcpy(&conn->wbuf[conn->wbuf_contents_size], &wlen, 4);
    memcpy(&conn->wbuf[conn->wbuf_contents_size + 4], out.data(), out.size());
    conn->wbuf_contents_size += 4 + wlen;
  } else {
    conn->resp_cache.swap(out);
    conn->state = STATE_RES;
    return false;
  }

  // update data read
  conn->rbuf_consumed += 4 + len;

  if (conn->rbuf_consumed == conn->rbuf_contents_size) {
    conn->state = STATE_RES;
    state_res(conn);
  }

  // continue the outer loop if the request was fully processed
  return (conn->state == STATE_REQ);
}

static bool try_flush_buffer(Conn *conn) {
  ssize_t rv = 0;
  do {
    size_t remain = conn->wbuf_contents_size - conn->wbuf_sent;
    rv = write(conn->fd, &conn->wbuf[conn->wbuf_sent], remain);
  } while (rv < 0 && errno == EINTR);
  if (rv < 0 && errno == EAGAIN) {
    return false;
  }
  if (rv < 0) {
    msg("write() error");
    conn->state = STATE_END;
    return false;
  }
  conn->wbuf_sent += rv;
  assert(conn->wbuf_sent <= conn->wbuf_contents_size);
  if (conn->wbuf_sent == conn->wbuf_contents_size) {
    // response complete, reset to request state
    conn->state = STATE_REQ;
    conn->wbuf_contents_size = 0;
    conn->wbuf_sent = 0;
    return false;
  }
  // otherwise there's still some data to deal with, proceed to
  // next iteration
  return true;
}

// state machine writer
static void state_res(Conn *conn) {
  while (try_flush_buffer(conn)) {
  }
}

// state machine reader
static void state_req(Conn *conn) {
  while (try_fill_buffer(conn)) {
  }
}

// state machine for client connections:
static void connection_io(Conn *conn) {
  if (conn->state == STATE_REQ) {
    state_req(conn);
  } else if (conn->state == STATE_RES) {
    state_res(conn);
  } else {
    assert(0); // not expected
  }
}

// create a kqueue. this involves registering the listening port
// with the kqueue, with the event to watch for being EV_READ, which
// translates to incoming connections on a listening socket. the flags
// EV_ADD and EV_ENABLE mean this incoming connections will be added to
// the kqueue and allow `kevent()` to return the event if triggered.
int new_listening_kqueue(int fd) {
  int kq = kqueue();
  if (kq < 0) {
    msg("kqueue() error");
    return -1;
  }

  struct kevent change_event = {};
  // EV_SET macro can simplify this initialisation.
  change_event.ident = fd;
  change_event.filter = EVFILT_READ;
  change_event.flags = EV_ADD | EV_ENABLE;
  change_event.fflags = 0;
  change_event.data = 0;
  change_event.udata = 0;

  if (kevent(kq, &change_event, 1, NULL, 0, NULL) < 0) {
    msg("kevent() error");
    return -1;
  }

  return kq;
}

int main() {
  // Create a TCP socket. PF_INET is for IPV4, SOCK_STREAM is for TCP.
  int serverfd = socket(PF_INET, SOCK_STREAM, 0);
  // Configure the socket to reuse it's address on restart.
  int val = 1;
  // SOL_SOCKET states that the level we are concerned with options
  // for is the socket itself. SO_REUSEADDR is the option we are
  // concerned with, and the pointer to `val` provides the value
  // we want to set. The option value is arbitrary bytes, so we
  // must provide its size.
  setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  //======================
  // Binding an address
  //======================
  struct sockaddr_in addr = {};
  addr.sin_family = PF_INET;
  // Using wildcard address 0.0.0.0:1234
  // htons and htonl are host-to-network short
  // and long respectively.
  addr.sin_port = htons(1234);
  addr.sin_addr.s_addr = htonl(0); // 0.0.0.0

  int rv = bind(serverfd, (const sockaddr *)&addr, sizeof(addr));
  if (rv) {
    die("bind()");
  }

  // Second argument to `listen()` is backlog, the maximum queue
  // length for waiting connections. After `listen()` the OS will
  // automatically handle TCP handshakes etc.
  rv = listen(serverfd, SOMAXCONN);
  if (rv) {
    die("listen()");
  }

  // ========================
  // event loop:
  // ========================
  // map of client connections, keyed by fd because fds start at 0 and
  // increment by 1
  std::vector<Conn *> fd2conn;

  // set listening socket to nonblocking
  fd_set_nb(serverfd);

  // event loop
  int kq = new_listening_kqueue(serverfd);
  while (true) {
    // connection fds, make sure they're all in the event queue
    for (Conn *conn : fd2conn) {
      if (!conn) {
        continue;
      }
      struct kevent event_to_add = {};
      event_to_add.ident = conn->fd;
      event_to_add.filter = EVFILT_READ;
      event_to_add.flags = EV_ADD;
      event_to_add.fflags = 0;
      event_to_add.data = 0;
      event_to_add.udata = NULL;
      if (kevent(kq, &event_to_add, 1, NULL, 0, NULL) < 0) {
        msg("kevent() placement error");
        return -1;
      }
    }

    // TODO: Figure out what goes into optimising event array size and number
    // of events retrieved at once
    struct kevent event[10];
    // check for events, only handle one per iteration of the event loop.
    // this blocks indefinitely when there are no events. is that ok?
    int new_events = kevent(kq, NULL, 0, event, 1, NULL);
    if (new_events < 0) {
      msg("kevent() retrieval error");
      return -1;
    } else if (new_events == 0) {
      msg("no events");
      continue;
    }

    // process active connections, skipping the listening socket
    int event_fd = event->ident;
    if (event_fd == serverfd) {
      // new connection request, accept
      (void)accept_new_conn(fd2conn, serverfd);
    } else if (event->flags & EVFILT_READ) {
      Conn *conn = fd2conn[event_fd];
      if (event->flags & EV_EOF) {
        // client has closed
        conn->state = STATE_END;
      } else {
        connection_io(conn);
      }
      if (conn->state == STATE_END) {
        // Client closed or something bad happened, clean up
        fd2conn[conn->fd] = NULL;
        (void)close(conn->fd);
        free(conn);
      }
    }
  }

  return 0;
}
