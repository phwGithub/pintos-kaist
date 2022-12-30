#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "kernel/console.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"

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
#define	STDIN_FILENO	0
#define	STDOUT_FILENO	1
#define MAX_FD_NUM		(1<<9)

static struct lock filesys_lock;

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

	lock_init(&filesys_lock);
}

/* helper functions starts */

static struct file *
fd_to_struct_filep(int fd) {
	if (fd < 0 || fd >= MAX_FD_NUM){
		return NULL;
	}
	struct thread * current = thread_current();
	return current->fd_table[fd];
}

static int 
add_file_to_fd_table(struct file *file){
	struct thread * current = thread_current();

	while(current->fd_table[current->fd_idx] != NULL && current->fd_idx < MAX_FD_NUM){
		current->fd_idx++;
	}
	if(current->fd_idx >= MAX_FD_NUM){
		return -1;
	}
	current->fd_table[current->fd_idx] = file;
	return current->fd_idx;
}

static void 
remove_file_from_fd_table(int fd){
	struct thread * current = thread_current();
	if (fd < 0 || fd >= MAX_FD_NUM){
		return;
	}	
	current->fd_table[fd] = NULL;
}  

static void
check_address(void *addr) {
	struct thread *cur = thread_current();
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL) {
		exit(-1);
	}
}

/* system calls start */

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *current = thread_current();
	current->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit ();
}

tid_t 
fork(const char *thread_name, struct intr_frame *f) {
    return process_fork(thread_name, f);
}

int 
exec(char *file_name) {
	check_address(file_name);

	char *fn_copy;
	
	int size = strlen(file_name) + 1;
	fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) {
		exit(-1);
	}
	strlcpy (fn_copy, file_name, size);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

int 
wait(tid_t child_tid) {
    return process_wait(child_tid);
}

bool
create(const char *file, unsigned initial_size) {
    check_address(file);

	lock_acquire(&filesys_lock);
	bool return_value = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return return_value;
}

bool
remove(const char *file) {
	check_address(file);

    lock_acquire(&filesys_lock);
	bool return_value = filesys_remove(file);
	lock_release(&filesys_lock);
	return return_value;
}

int 
open (const char *file) {
	check_address(file);

	lock_acquire(&filesys_lock);
	struct file * open_file = filesys_open(file);
	lock_release(&filesys_lock);
	if(open_file == NULL){
		return -1;
	}
	int fd = add_file_to_fd_table(open_file);
	if (fd == -1){
		file_close(open_file);
	}
	return fd;
}

int
filesize(int fd) {
    struct file *open_file = fd_to_struct_filep(fd);
    if (open_file == NULL)
    {
        return -1;
    }

	lock_acquire(&filesys_lock);
	int file_size = file_length(open_file);
	lock_release(&filesys_lock);

    return file_size;
}

void
seek (int fd, unsigned position) {
    struct file *open_file = fd_to_struct_filep(fd);
    if (open_file == NULL || open_file == 2)
    {
        return -1;
    }

	lock_acquire(&filesys_lock);
	file_seek(open_file, (off_t)position);
	lock_release(&filesys_lock);
}

unsigned
tell (int fd) {
    struct file *open_file = fd_to_struct_filep(fd);
    if (open_file == NULL)
    {
        return -1;
    }

	lock_acquire(&filesys_lock);
	unsigned pos = file_tell(open_file);
	lock_release(&filesys_lock);

	return pos;
}

int 
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);

	off_t read_byte;
	uint8_t *read_buffer = buffer;
	if(fd == STDIN_FILENO) {
		char key;
		for (read_byte = 0; read_byte < size; read_byte++){
			key = input_getc();
			*read_buffer++ = key;
			if(key == '\0'){
				break;
			}
		}
	}
	else if(fd == STDOUT_FILENO){
		return -1;
	}
	else {
		struct file * read_file = fd_to_struct_filep(fd);
		if(read_file == NULL || read_file == 2){
			return -1;
		}
		lock_acquire(&filesys_lock);
		read_byte = file_read(read_file, buffer, size);
		lock_release(&filesys_lock);
	}
	return read_byte;
}

int
write (int fd, const void *buffer, unsigned size){
	check_address(buffer);

    int write_result;

    if (fd == STDIN_FILENO) // stdin
    {
        return 0;
    }
    else if (fd == STDOUT_FILENO) // stdout
    {
        putbuf(buffer, size);
        return size;
    } else {
		struct file * write_file = fd_to_struct_filep(fd);
		if(write_file == NULL || write_file == 1){
			return 0;
		}
		lock_acquire(&filesys_lock);
		off_t write_byte = file_write(write_file, buffer, size);
		lock_release(&filesys_lock);
		return write_byte;
	}
}

void 
close (int fd){
	struct file *close_file = fd_to_struct_filep(fd);
	
	if(close_file == NULL){
		return;
	}

	if (fd <= 1 || close_file <= 2) {
		return;
	}

	remove_file_from_fd_table(fd);

	//lock_acquire(&filesys_lock);
	file_close(close_file);
	//lock_release(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	int syscall_num = f->R.rax;

	// a1 = f->R.rdi
	// a2 = f->R.rsi
	// a3 = f->R.rdx
	// a4 = f->R.r10
	// a5 = f->R.r8
	// a6 = f->R.r9
	// return = f->R.rax

	//printf("syscall %d !!!!!!!!!!!!!!!!!!!\n", syscall_num);
	switch (syscall_num)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1) 
			{
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;

		default:
			break;
	}

}
