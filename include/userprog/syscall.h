#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* -------------------------------------------------------- PROJECT2 : User Program - System Call -------------------------------------------------------- */
void check_address (void *addr); // 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 하는 함수 선언
void halt (void); // 핀토스 종료 시스템 콜 함수 선언
void exit (int status); // 현재 프로세스를 종료시키는 시스템 콜 함수 선언

int wait (int pid);
int write (int fd, const void *buffer, unsigned size);
/* -------------------------------------------------------- PROJECT2 : User Program - System Call -------------------------------------------------------- */

#endif /* userprog/syscall.h */
