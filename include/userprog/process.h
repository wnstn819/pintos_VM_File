#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* -------------------------------------------------------- PROJECT2 : User Program - Argument Passing -------------------------------------------------------- */
void argument_stack (char **argv, int argc, struct intr_frame *_if); // parsing한 arguments를 user stack에 넣어주는 함수
struct thread *get_child_process(int);
/* -------------------------------------------------------- PROJECT2 : User Program - Argument Passing -------------------------------------------------------- */

#endif /* userprog/process.h */
