#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
/* 시스템 콜 인터페이스 메인 함수 */
void
syscall_handler (struct intr_frame *f UNUSED) {
/* -------------------------------------------------------- PROJECT2 : User Program - System Call -------------------------------------------------------- */
	int system_call_number = f->R.rax; // 호출한 시스템 콜 번호를 저장하는 변수 선언
	switch(system_call_number) {
		case SYS_HALT :
			halt ();
			break;
		case SYS_EXIT :
			exit (f->R.rdi);
			break;
		// case SYS_FORK :
		// 	fork (f->R.rdi);
		// 	break;
		// case SYS_EXEC :
		// 	exec (f->R.rdi);
		// 	break;
		// case SYS_WAIT :
		// 	wait (f->R.rdi);
		// 	break;
		// case SYS_CREATE :
		// 	create (f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_REMOVE :
		// 	remove (f->R.rdi);
		// 	break;
		// case SYS_OPEN :
		// 	open (f->R.rdi);
		// 	break;
		// case SYS_FILESIZE :
		// 	filesize (f->R.rdi);
		// 	break;
		// case SYS_READ :
		// 	read (f->R.rdi, f->R.rsi, f->R.rdx);
		// 	break;
		case SYS_WRITE :
			printf("%s", f->R.rsi);
			//write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK :
		// 	seek (f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL :
		// 	tell (f->R.rdi);
		// 	break;
		// case SYS_CLOSE :
		// 	close (f->R.rdi);
		// 	break;
		default :
			exit(-1);
			break;
	}

	// printf ("system call!\n");
	// thread_exit ();
}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 하는 함수 */
/* 주소유효성 겸사 : 포인터가 가리키는 주소가 사용자 영역(0x8048000~0xc0000000)인지 확인 */
/* 유저 영역을 벗어난 영역인 경우 프로세스 종료(exit(-1)) */
void
check_address (void *addr) {
	struct thread *cur = thread_current ();
	// 현재 접근하는 메모리 주소가 NULL이거나, 커널 영역에서 사용하는 주소이거나, 유저 영역에서 사용하는 주소이지만 페이지로 할당되지 않은 주소일 경우(=잘못된 접근)
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL) {
		exit(-1); // 프로세스 종료
	}
}

/* 핀토스 종료 시스템 콜 함수 */
void
halt (void) {
	power_off (); // HALT 시스템 콜 호출 시, init.c의 power_off() 함수로 핀토스를 종료
}

/* 현재 프로세스를 종료시키는 시스템 콜 함수 */
void
exit (int status) {
	struct thread *cur = thread_current (); // 실행중인 현재 스레드 구조체를 curr에 저장
	cur->exit_status = status; // 현재 스레드 종료 상태 저장(0이면 정상 종료)
	printf("%s: exit(%d)\n", thread_name (), status); // 프로세스 종료 메시지 출력
	thread_exit(); // 스레드 종료
}

int
wait (int pid) {
	return process_wait (pid);
}

int
write (int fd, const void *buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
    }
    return size;
}
/* -------------------------------------------------------- PROJECT2 : User Program - System Call -------------------------------------------------------- */
