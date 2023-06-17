/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */

/*
페이지 구조체를 할당하고 페이지 타입에 맞는 적절한 초기화 함수를 세팅

 초기화되지 않은 주어진 type의 페이지를 생성한다. 초기화되지 않은 페이지의 swap_in 핸들러는 자동적으로 페이지 타입에 맞게 페이지를 초기화하고
 주어진 AUX를 인자로 삼는 INIT 함수를 호출합니다.
 페이지 구조체를 가지게 되면 프로세스의 보조 페이지 테ㅕ이블에 그 페이지를 삽입한다. 
 vm.h -> VM_TYPE 매크로를 사용하면 편하다.
*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/*
	va에 해당하는 구조체 페이지를 찾아 반환한다.
*/
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
    struct hash_elem *e;

	// va에 해당하는 hash_elem 찾기
    page->va = pg_round_down(va); // page의 시작 주소 할당
	e = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page);

	// 있으면 e에 해당하는 페이지 반환
    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
/*
	supplementary page table에 struct page를 삽입
	가상 주소가 이미 supplementary page tabledp 존재하는지 확인
	 - 존재하지 않으면 삽입
*/
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */
	return hash_insert(&spt->spt_hash, &page->hash_elem) == NULL ? true : false; // 존재하지 않을 경우에만 삽입
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/*
  palloc_get_page()를 호출함으로써 메모리 풀에서 새로운 물리메모리 페이지를 가져옴.
  메모리 풀에서 페이지를 성공적으로 가져오면, 프레임을 할당하고 프레임 구조체의 멤버들을 초기화한 후 프레임을 반환
*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	 void *kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

    if (kva == NULL)   // page 할당 실패 -> 나중에 swap_out 처리
        PANIC("todo"); // OS를 중지시키고, 소스 파일명, 라인 번호, 함수명 등의 정보와 함께 사용자 지정 메시지를 출력

	frame = malloc(sizeof(struct frame)); // 프레임 할당
    frame->kva = kva;                      // 프레임 멤버 초기화

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/*
1. 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾는다.
2. 페이지를 저장하기 위해 프레임을 획득합니다.
3. 데이터를 파일 시스템이나 스왑에서 읽어오거나, 0으로 초기화
4. 폴트가 발생한 가상주소에 대한 페이지 테이블 엔트리가 물리 페이지를 가리키도록 지정합니다. mmu.c의 함수를 사용
 P3_TODO:
*/
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/*
인자로 주어진 va에 페이지를 할당하고, 해당 페이지에 프레임을 할당.
*/
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	// spt에서 va에 해당하는 page 찾기
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/*
인자로 주어진 page에 물리 모메로 프레임을 할당. vm_get_frame으로 프레임 하나를 얻고, 그 이후 MMU를 세팅( 가상 주소와 물리 주소를 매핑한 정보를
페이지 테이블에 추가 해야 함)
위의 연산이 성공할 경우 true, 아닌 경우 false
*/
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	// 가상 주소와 물리 주소를 매핑
    struct thread *current = thread_current();
	bool writable = is_writable(current->pml4); // 🚨 Todo
	pml4_set_page(current->pml4, page->va, frame->kva, writable);	

    return swap_in(page, frame->kva); // uninit_initialize
}

/* Initialize new supplemental page table */
/*
	P3_TODO: 페이지를 초기화 한다. 새로운 프로세스가 시작될 때와 프로세스가 포크될 때 호출된다.
*/
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}


/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}



/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}