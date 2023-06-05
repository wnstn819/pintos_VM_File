#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
	unsigned value;             /* Current value. */
	struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock {
	struct thread *holder;      /* Thread holding lock (for debugging). */
	struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition {
	struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

/* Optimization barrier.
 *
 * The compiler will not reorder operations across an
 * optimization barrier.  See "Optimization Barriers" in the
 * reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

/* --------------------------------------------------- PROJECT1 : Threads - Priority Scheduling(Synchronization) --------------------------------------------------- */
/* semaphore_elem가 나타내는 세마포어의 waiters 리스트의 맨 앞 스레드끼리 우선순위를 비교하는 함수 선언 */
bool cmp_sem_priority (const struct list_elem *a, const struct list_elem *b, void *aux);
/* --------------------------------------------------- PROJECT1 : Threads - Priority Scheduling(Priority Invension) --------------------------------------------------- */

/* --------------------------------------------------- PROJECT1 : Threads - Priority Scheduling(Priority Invension) --------------------------------------------------- */
bool cmp_donate_priority (const struct list_elem *a, const struct list_elem *b, void *aux);
void donate_priority (void);
void remove_with_lock(struct lock *lock);
void refresh_priority(void);
/* --------------------------------------------------- PROJECT1 : Threads - Priority Scheduling(Synchronization) --------------------------------------------------- */

#endif /* threads/synch.h */
