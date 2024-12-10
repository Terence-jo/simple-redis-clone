#include "threadpool.h"
#include <cassert>
#include <cstddef>

// the consumer for the threads
static void *worker(void *arg) {
  // ThreadPool gets passed to worker as a void * by the thread
  ThreadPool *tp = (ThreadPool *)arg;
  while (true) {
    pthread_mutex_lock(&tp->mu);
    // wait for the cond: non-empty queue. this always needs to be inside
    // a loop checking the condition manually.
    while (tp->queue.empty()) {
      // release mutex, wait for condition, reacquire mutex and continue.
      // after waking it will check the while condition again in case
      // it has been changed before acquisition of the mutex.
      pthread_cond_wait(&tp->not_empty, &tp->mu);
    }

    // got the job
    Work w = tp->queue.front();
    tp->queue.pop_front();
    pthread_mutex_unlock(&tp->mu);

    w.f(w.arg);
  }
  return NULL;
}

// initialise ThreadPool and all component pthread types
void thread_pool_init(ThreadPool *tp, size_t num_threads) {
  assert(num_threads > 0);

  int rv = pthread_mutex_init(&tp->mu, NULL);
  assert(rv == 0);
  rv = pthread_cond_init(&tp->not_empty, NULL);
  assert(rv == 0);

  tp->threads.resize(num_threads);
  for (size_t i = 0; i < num_threads; i++) {
    int rv = pthread_create(&tp->threads[i], NULL, &worker, tp);
    assert(rv == 0);
  }
}

// take function and argument, create work and add it to the queue
void thread_pool_queue(ThreadPool *tp, void (*f)(void *), void *arg) {
  Work w;
  w.f = f;
  w.arg = arg;

  pthread_mutex_lock(&tp->mu);
  tp->queue.push_back(w);
  pthread_cond_signal(
      &tp->not_empty); // doesn't necessarily need mutex protection
  pthread_mutex_unlock(&tp->mu);
}
