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
  RES_OK = 0,
  RES_ERR = 1,
  RES_NX = 2,
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
static uint32_t do_get(const std::vector<std::string> &cmd, unsigned char *res,
                       uint32_t *reslen) {
  if (!g_map.count(cmd[1])) {
    // key does not exist
    return RES_NX;
  }
  std::string &val = g_map[cmd[1]];
  assert(val.size() <= k_max_msg);
  memcpy(res, val.data(), val.size());
  *reslen = (uint32_t)val.size();
  return RES_OK;
}

static uint32_t do_set(const std::vector<std::string> &cmd, unsigned char *res,
                       uint32_t *reslen) {
  (void)res;
  (void)reslen;
  g_map[cmd[1]] = cmd[2];
  return RES_OK;
}

static uint32_t do_del(const std::vector<std::string> &cmd, unsigned char *res,
                       uint32_t *reslen) {
  // map.erase() does not throw exceptions if the element isn't there
  (void)res;
  (void)reslen;
  g_map.erase(cmd[1]);
  return RES_OK;
}

static int32_t do_request(const unsigned char *req, uint32_t reqlen,
                          uint32_t *rescode, unsigned char *res,
                          uint32_t *reslen) {
  std::vector<std::string> cmd;
  if (0 != parse_req(req, reqlen, cmd)) {
    msg("bad req");
    return -1;
  }
  if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
    *rescode = do_get(cmd, res, reslen);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
    *rescode = do_set(cmd, res, reslen);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
    *rescode = do_del(cmd, res, reslen);
  } else {
    // cmd is not recognised
    *rescode = RES_ERR;
    const char *msg = "Unkown cmd";
    strcpy((char *)res, msg);
    *reslen = strlen(msg);
    return 0; // leave request protocol errors to the client
  }
  return 0;
}

static bool try_one_request(Conn *conn) {
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

  // got a request, generate a response
  // first parse the command and put response in buffer with space
  // for the length and response code.
  size_t wbuf_msg_start = conn->wbuf_contents_size + 4 + 4;
  size_t next_size = wbuf_msg_start + len;
  if (next_size <= sizeof(conn->wbuf)) {
    uint32_t wlen = 0;
    uint32_t rescode = 0;
    int32_t err = do_request(&conn->rbuf[conn->rbuf_consumed + 4], len,
                             &rescode, &conn->wbuf[wbuf_msg_start], &wlen);
    if (err) {
      conn->state = STATE_END;
      return false;
    }
    wlen += 4;
    memcpy(&conn->wbuf[conn->wbuf_contents_size], &wlen, 4);
    memcpy(&conn->wbuf[conn->wbuf_contents_size + 4], &rescode, 4);
    conn->wbuf_contents_size +=
        4 + wlen; // wlen includes the rescode, then +4 for wlen
  } else {
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
  // map of client connections, keyed by fd because fds start at 0 and increment
  // by 1
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
