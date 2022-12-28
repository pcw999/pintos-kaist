#include <stdio.h>
#include <syscall-nr.h>
#include "lib/user/syscall.h" //for syscall fuction
#include "intrinsic.h"
#include "lib/string.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
int add_file_to_fdt(struct file *file);
static struct file *find_file_by_fd(int fd);
void remove_file_fdt(int fd);
pid_t fork(const char *thread_name, struct intr_frame *f);

struct lock file_lock;

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

	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	int number = f->R.rax;
	switch(number) {
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
			if(exec(f->R.rdi) == -1) {
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
			return -1;
	}
}

void check_address(void *addr) {
	if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(thread_current()->pml4, addr) == NULL) {
		exit(-1);
	}
}

int add_file_to_fdt(struct file *file) {
	struct thread *cur = thread_current();
	struct file **fdt = cur->fd_table;

	while(cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx]) {
		cur->fd_idx++;
	}

	if(cur->fd_idx >= FDCOUNT_LIMIT) {
		return -1;
	}

	fdt[cur->fd_idx] = file;
	return cur->fd_idx;
}

void remove_file_fdt(int fd) {
	struct thread *cur = thread_current();
	if(fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}
	cur->fd_table[fd] = NULL;
}

static struct file *find_file_by_fd(int fd) {
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	return cur->fd_table[fd];
}

void halt(void) {
	printf("Power Off..\n");
	power_off();
}

void exit(int status) {
	struct thread *cur = thread_current();
	cur->exit_status = status;
	
	thread_exit();
}

pid_t fork(const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int exec(const char *file) {
	check_address(file);

	int file_size = strlen(file)+1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if(fn_copy == NULL) {
		return -1;
	}
	strlcpy(fn_copy, file, filesize);

	if(process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

int wait(pid_t pid) {
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);
	if(open_file == NULL) {
		return -1;
	}
	int fd = add_file_to_fdt(open_file);

	if(fd==-1) {
		file_close(open_file);
	}

	return fd;
}

int filesize(int fd) {
	struct file *open_file = find_file_by_fd(fd);
	if(open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	if(fd == 0) {
		char input_data[size+1];
		int i=0;
		while(i < size) {
			input_data[i] = input_getc();
			if(input_data[i] == '\0') {
				break;
			}
			i++;
		}
		buffer = input_data;
		return i; 
	}
	struct file *read_file = find_file_by_fd(fd);
	if(read_file == NULL || read_file == 2) {
		return -1;
	}
	
	lock_acquire(&file_lock);
	int return_value = file_read(read_file, buffer, size);
	lock_release(&file_lock);

	return return_value;
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	struct file *write_file = find_file_by_fd(fd);
	if(write_file == NULL || write_file == 1) {
		return -1;
	}
	else if(write_file == 2) {
		putbuf(buffer, size);
		return size;
	}
	lock_acquire(&file_lock);
	int return_value = file_write(write_file, buffer, size);
	lock_release(&file_lock);

	return return_value;
}

void seek(int fd, unsigned position) {
	struct file *seek_file = find_file_by_fd(fd);
	if(seek_file <= 2) {
		return;
	}
	file_seek(seek_file, position);
}

unsigned tell(int fd) {
	struct file *tell_file;
	return file_tell(tell_file);
}

void close(int fd) {
	struct file *close_file = find_file_by_fd(fd);
	if (close_file == NULL) {
		return;
	}
	remove_file_fdt(fd);
	if(fd<=1 || close_file<=2) {
		return;
	}
	file_close(close_file);
}