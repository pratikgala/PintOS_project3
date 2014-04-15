#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#include "devices/input.h"
#include "devices/shutdown.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"

#include "vm/page.h"

#define USER_B_ADDR ((void *) 0x08048000)
//----------------------------------------------------------------------
static void * fetch_arg (void **,int);
void verify_valid_ptr(const void *ptr_addr);

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t);
int create (const char *file, unsigned initial_size);
int remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer_, unsigned size);
int write (int fd, void *buffer_, unsigned size);
int seek (int fd, unsigned position);
int tell (int fd);
int close (int fd);
static int mmap (int id, void *address);
static int munmap (int mapping);

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
//----------------------------------------------------------------------
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}// end of syscall_init
//----------------------------------------------------------------------
static void
syscall_handler (struct intr_frame *f) 
{
	//verify the validity of the pointer
	verify_valid_ptr((const void*)f->esp);
	//get the syscall number
    int sys_call_num = *(int *)f->esp;
	int status;
	const char* ufile;
	pid_t pidt;
	const char* file;
	unsigned size ;
	int fsize;
	int fd1 ;
	void* buf;
	int arg1;
	unsigned* arg2;
	int arg3;
	mmapid_t arg4;
	
    switch(sys_call_num) {
      case SYS_HALT:
        halt();
        NOT_REACHED();
      case SYS_EXIT:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		status = *(int *)fetch_arg(&(f->esp), 4);
        exit(status);
        NOT_REACHED();
      case SYS_EXEC:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		ufile=*(const char **)fetch_arg(&(f->esp) ,4);
		f->eax = (pid_t) exec((const char *)ufile);
        break;
      case SYS_WAIT:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		pidt = *(pid_t *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) wait(pidt);
        break;
      case SYS_CREATE:
		file = *(const char **) fetch_arg(&(f->esp), 16);
		size = *(unsigned *) fetch_arg (&(f->esp), 20);
		f->eax = (uint32_t)create ((const char *)file, size);
        break;
      case SYS_REMOVE:
		file = *(const char **) fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) remove((const char *)file);
        break;
      case SYS_OPEN:
		file = *(const char **) fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) open((const char *)file);
        break;	
      case SYS_FILESIZE:
		fsize = *(int *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) filesize(fsize);
        break;
      case SYS_READ:
		fd1 = *(int *)fetch_arg(&(f->esp), 20);
		buf = *(void **) fetch_arg(&(f->esp), 24);
		size = *(unsigned *) fetch_arg (&(f->esp), 28);
        f->eax = (uint32_t) read(fd1,(const void *)buf,size);
        break;
      case SYS_WRITE:
		fd1 = *(int *)fetch_arg(&(f->esp), 20);
		buf = *(void **) fetch_arg(&(f->esp), 24);
		size = *(unsigned *) fetch_arg (&(f->esp), 28);
        f->eax = (uint32_t) write(fd1,(const void *)buf,size);
        break;
      case SYS_SEEK:
		arg1 =*(int *)fetch_arg(&(f->esp), 16);
		arg2 = *(unsigned *) fetch_arg (&(f->esp), 20);
        f->eax=(uint32_t) seek(arg1,arg2);
        break;
      case SYS_TELL:
		arg1 =*(int *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) tell(arg1);
        break;
      case SYS_CLOSE:
		arg1 =*(int *)fetch_arg(&(f->esp), 4);
        f->eax=(int) close(arg1);
        break;
	  case SYS_MMAP:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 16));
		verify_valid_ptr((const void*)fetch_arg(&(f->esp), 20));
		arg1 =*(int *)fetch_arg(&(f->esp), 16);
		buf = *(void **) fetch_arg(&(f->esp), 20);
        f->eax = (int) mmap(arg1,buf);
        break;
      case SYS_MUNMAP:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		arg1 =*(int *)fetch_arg(&(f->esp), 4);
        munmap(arg1);
        break;	
      default:
        printf("This system call is not implemented!");
        thread_exit();
        break;
	}//end of switch
}//end of syscall_handler

//----------------------------------------------------------------------
/* file descriptor structure */
struct file_descriptor
  {
    struct list_elem elem;      // List element
    struct file *file;          // File
    int id;                 	// File id
  };

  

/* Map structure binds a map id to a specific region of memory and a file. */
struct map
  {
    struct list_elem elem;      // List element
	struct file *file;          // File
	size_t num_of_pages;        //Number of pages mapped
    int map_id;                 // Mapping id   
    uint8_t *start_addr;        //Start of memory mapping
    
  };


  
/* --------------- Helper functions for the system calls -----------*/

/* check for the valid pointer by check the pointer address is less 
   than the user bottom address and is user's address valid */
	void verify_valid_ptr(const void *ptr_addr)
	{
		if(ptr_addr < USER_B_ADDR || !is_user_vaddr(ptr_addr)){
		    //printf("\n bad addr\n");
			exit(-1);
		}//end of if
	}//end of verify_valid_ptr

/* return argument at the calculated stack address i.e the
   esp pointer + offset*/
static void *
fetch_arg (void **esp, int offset)
{
	return (void *)(*esp + offset);
}//end of fetch_arg

//----------------------------------------------------------------------
/*this function will iterate through the list of file descriptors of the
  current thread and terminates if the fd is not associated with the
  current thread i.e the current open file*/
  
	static struct file_descriptor *
	get_file_desc (int fd) 
	{
	  struct thread *cur = thread_current ();
	  struct list_elem *ele;
	   
	  for (ele = list_begin (&cur->file_descs);
		   ele != list_end (&cur->file_descs);
		   ele = list_next (ele)){
		  struct file_descriptor *f_d;
		  f_d = list_entry (ele, struct file_descriptor, elem);
		  if (f_d->id == fd)
			return f_d;
		}//end of for
	  thread_exit ();
	}// //end of get_file_desc
	

//----------------------------------------------------------------------  
/* Returns the map associated with the given id.Terminates the process 
   if ID is not associated with a memory mapping. */

static struct map *
get_map (int id) 
{
  struct thread *cur = thread_current ();
  struct list_elem *ele;
   
  for (ele = list_begin (&cur->map_list); ele != list_end (&cur->map_list);
       ele = list_next (ele)){
      struct map *mp = list_entry (ele, struct map, elem);
      if (mp->map_id == id){
        return mp;
	  }//end of if
    }//end of for
  //exit	
  thread_exit ();
}//end of get_map

//----------------------------------------------------------------------
/* Creates a copy of user string in kernel memory and returns it as a 
   page that must be freed with palloc_free_page().
   Truncate the string at PGSIZE bytes in size.
   If any of the user accesses are invalid call thread_exit(). */
static char *
usrStr_copyTo_kerMem (const char *user_str) 
{
  char *kernel_str;
  size_t len;
  char *usr_pg;
  kernel_str = palloc_get_page (0);
  if (kernel_str == NULL){
		// exit thread
		thread_exit ();
  }// end of if

  len = 0;
  while(1) 
    {
      usr_pg = pg_round_down (user_str);
      if (!lock_this_page (usr_pg, false)){
        goto page_not_lock;
	  }// end of if

      for (; user_str < usr_pg + PGSIZE; user_str++) {
			kernel_str[len++] = *user_str;
			if (*user_str == '\0'){
				// unlock the page
				unlock_this_page (usr_pg);
				//return the kernel string after unlocking the page
				return kernel_str; 
			}// end of if
			else if (len >= PGSIZE){
				goto len_long;
			}// end of else
        }// end of for
	  // unlock the page
      unlock_this_page (usr_pg);
    }// end of while

len_long:
  unlock_this_page (usr_pg); // unlock kernel page
   
page_not_lock:
  palloc_free_page (kernel_str); // free kernel page
  thread_exit (); 	// exit the thread
}//end of usrStr_copyTo_kerMem


/* Remove map M from the virtual address space,
   writing back any pages that have changed. */
static void
unmap (struct map *mapping) 
{
	//get the virtual start addr
	void *vaddr=(void *) mapping->start_addr;
	size_t iter;
	// iterate through the number of pages
	for(iter = 0 ; iter < mapping->num_of_pages ; iter++){
		// deallocate the address from the page
		deallocation_of_page (vaddr);
		// add the page size to the address
		vaddr=vaddr + PGSIZE;
	}//end of for
	// remove all the list mappings
	list_remove (&mapping->elem);
	// call function free to free mappings
	free(mapping);
}//end of unmap


/* ------------------------ system calls ---------------------------*/

// Halt system call. 
//----------------------------------------------------------------------
void halt (void)
{
  shutdown_power_off ();
}//end of halt


// Exit system call.
//----------------------------------------------------------------------
void exit (int status) 
{
  struct thread *cur=thread_current (); 
  //set the finish of the current thread as the status i.e exit code
  thread_current ()->finish=status; 
  //call thread_exit function which will then call process_exit()
  // and syscall_exit() functions to update the status of the child 
  //threads and also to close all the open files
  thread_exit ();
  NOT_REACHED ();
}//end of exit	

	
// Exec system call. 
//----------------------------------------------------------------------
pid_t exec (const char *cmd_line) 
{
  char *ker_f = usrStr_copyTo_kerMem (cmd_line);
  tid_t tid;
  //acquire the lock
  lock_acquire (&file_lock);
  //call process execute
  tid = process_execute (ker_f);
  //once we get the tid release the lock
  lock_release (&file_lock);
  //free the page
  palloc_free_page (ker_f);
 //return the tid
  return tid;
}//end of exec
 
 
 // Wait system call 
 //----------------------------------------------------------------------
int wait (pid_t child) 
{
	// this function will call process_wait function which is in 
	// process.c that returns its exit status.
	return process_wait (child);
}//end of wait


// Create system call 
//----------------------------------------------------------------------
int
create (const char *file, unsigned initial_size) 
{
  bool f_res;
  char *ker_f = usrStr_copyTo_kerMem (file);
  //acquire the file lock file_lock
  lock_acquire (&file_lock);
  //call the filesys_create function
  f_res = filesys_create (ker_f, initial_size);
  //release the lock once the status has been received
  lock_release (&file_lock);
  //free the page
  palloc_free_page (ker_f);
  //return the status received by the filesys_create
  return f_res;
}//end of create	
	

// Remove system call 
//----------------------------------------------------------------------
int
remove (const char *file) 
{
  bool f_res;
  char *ker_f = usrStr_copyTo_kerMem (file);
  //acquire the file lock file_lock
  lock_acquire (&file_lock);
  //call the filesys_remove function
  f_res = filesys_remove (ker_f);
  //release the lock once the status has been received
  lock_release (&file_lock);
  //free the page
  palloc_free_page (ker_f);
  //return the status received by the filesys_create
  return f_res;
}//end of remove

	
// Open system call. 
//----------------------------------------------------------------------
int open (const char *file) 
{
  struct file_descriptor *f_d;
  int file_desc = -1;
  
  char *ker_f = usrStr_copyTo_kerMem (file);
  
  f_d = malloc (sizeof *f_d);
  
  //check if file descriptor f_d is not null
  if (f_d != NULL){
	  //acquire the file lock file_lock
	  lock_acquire (&file_lock);
	  //call the filesys_open function and get the file
	  f_d->file = filesys_open (ker_f);
	  //check if the file is not null
	  if(f_d->file == NULL){
		//if the file is null then free the space
		free (f_d);
	  }//end of if
	  else{
		  struct thread *cur = thread_current ();
		  //set the file_desc
		  file_desc = f_d->id = cur->next_value++;
		  //update the list of file descriptors inside the thread
		  //structure and the elem inside the file struct
		  list_push_front (&cur->file_descs, &f_d->elem);
		}//end of else
		//release the lock
	  lock_release (&file_lock);
	}//end of if 
  //free the page
  palloc_free_page (ker_f);
  //return the file_desc
  return file_desc;
}//end of open

 	
// Filesize system call 
//----------------------------------------------------------------------
int filesize (int file_desc) 
{
  int f_size;
  struct file_descriptor *f_d = get_file_desc (file_desc);
  //acquire the file lock file_lock
  lock_acquire (&file_lock);
  //call the file_length function to get the size
  f_size = file_length (f_d->file);
  //release the file lock
  lock_release (&file_lock);
  // return the size
  return f_size;
}//end of filesize	


// Read system call 
//----------------------------------------------------------------------
int read (int fd, void *buffer_, unsigned size) 
{
	struct file_descriptor *f_d;
	uint8_t *read_buffer = buffer_;
	int total_bytes_read = 0;
	//$$--------------------------------------------------
	f_d = get_file_desc (fd);
	//$$--------------------------------------------------

  while (size > 0) {
		//page read, amount to read in this 
		
		off_t retval;
		// check the space left on the current page
		size_t rem_page_size;
		rem_page_size= PGSIZE - pg_ofs(read_buffer);
		//check the amount to be read and then start reading accordingly.
		size_t r_vol ;
		
		if(size<rem_page_size){
			r_vol=size;
		}//end of if
		else{
			r_vol=rem_page_size;
		}//end of else
	  
		if(fd!= STDIN_FILENO){
			if (!lock_this_page (read_buffer, true)) {
				thread_exit ();
			}//end of if 
			//acquire the file lock to start reading
			lock_acquire (&file_lock);
			retval = file_read (f_d->file, read_buffer, r_vol);
			lock_release (&file_lock);
			unlock_this_page(read_buffer);
		}//end of if
		else{
			size_t itr;
			for(itr =0;itr<r_vol;itr++){
				char ip_c=input_getc();
				if(!lock_this_page(read_buffer,true)){
					thread_exit();
				}//end of if

				read_buffer[itr]=ip_c;
				unlock_this_page(read_buffer);
			}//end of for
			total_bytes_read=r_vol;
		}//end of else
	  
		// start reading from file to a page 
		if (retval < 0){
			//set the total_bytes_read to -1 if it is 0
			if (total_bytes_read == 0){
				total_bytes_read = -1; 
			}//end of if	
			break;
        }//end of if 
		//increment the total_bytes_read to retval
        total_bytes_read= total_bytes_read  + retval;
		
		// If all the bytes have been read then break
		if (retval != (off_t) r_vol){
			break;
		}//end of if
		
		// update the size and read_buffer values according to the retval
		size =size- retval;
		read_buffer =read_buffer + retval;
    }//end of wjile
  //return the total total_bytes_read 
  return total_bytes_read;
}//end of read	


// Write system call. 
//----------------------------------------------------------------------
int write (int fd, void  *buffer_, unsigned size) 
{
	struct file_descriptor *f_d;
	f_d =  NULL;
	uint8_t *write_buffer = buffer_;
	int total_bytes_written = 0;

	// Lookup up file descriptor.
	if (fd != 1){
		f_d = get_file_desc (fd);
	}//end of if
	
	//loop till all the bytes have been written
	while (size > 0) 
    {
		off_t retval;
		// check how much space is left on the current page 
		size_t rem_page_size;
		rem_page_size = PGSIZE - pg_ofs(write_buffer);
		//check the amount to be written and then start reading accordingly.
		size_t w_vol;
		
		if(size < rem_page_size){
			w_vol=size;
		}//end of if
		else{
			w_vol=rem_page_size;
		}//end of else
		
		// write into file from page
		if (!lock_this_page (write_buffer, false)){
			// if user addr not valid exit thread
			thread_exit ();
		}//end of if	
		
		
		lock_acquire (&file_lock);
		// perform write operation by call putbuf() function
		if (fd == 1){
			//write the amount
			putbuf ((char *)write_buffer, w_vol);
			retval = w_vol;
		}//end of if
		else{
			retval = file_write (f_d->file, write_buffer, w_vol);
		}//end of else
		lock_release (&file_lock);	
		
		
		/* Release user page. */
		unlock_this_page (write_buffer);	
		
		if (retval < 0){
			//set the total_bytes_read to -1 if it is 0
			if (total_bytes_written == 0){
				total_bytes_written = -1;
			}//end of if
			break;
		}//end of if
		
		//increment the total_bytes_written to retval	
		total_bytes_written =total_bytes_written + retval;

		// If all the bytes have been written then break
		off_t check_write_amt=(off_t)w_vol;
		
		if (retval != check_write_amt){
			break;
		}//end of if	
		
		// update the size and write_buffer values according to the retval
		write_buffer = write_buffer + retval;
		size = size - retval;
    }//end of while

  return total_bytes_written; 
}//end of write


// Seek system call. 
//----------------------------------------------------------------------
int seek (int fd, unsigned position) 
{
	int success=0;
	//initialize the file descriptor
	struct file_descriptor *f_d = get_file_desc (fd);
	//acquire the file lock
	lock_acquire (&file_lock);
	//check the offset position and if it is greater than 0 then call 
	//file_seek() function
	if ((off_t) position >= 0)
	file_seek (f_d->file, position);
	//release the file lock once the seek operation is complete
	lock_release (&file_lock);
	//return success
	return success;
}//end of seek

// Tell system call 
//----------------------------------------------------------------------
int tell (int fd) 
{
	unsigned pos;
	//initialize the file descriptor with the fd input
	struct file_descriptor *f_d = get_file_desc (fd);
	//acquire the file lock
	lock_acquire (&file_lock);
	//get the pos by calling file_tell function
	pos = file_tell (f_d->file);
	//release the file lock once the pos is received
	lock_release (&file_lock);
	//return the pos
	return pos;
}//end of tell

// Close system call
//----------------------------------------------------------------------
int close (int fd) 
{
	int success=0;
	//initialize the file descriptor with the fd input
	struct file_descriptor *f_d = get_file_desc (fd);
	//acquire the file lock
	lock_acquire (&file_lock);
	//call the file_close function and close the file
	file_close (f_d->file);
	//release the file lock once the file has been close
	lock_release (&file_lock);
	//remove the file from the elem list in the file descriptor
	list_remove (&f_d->elem);
	//free the f_d
	free (f_d);
	//return success
	return success;
}//end of close


// Mmap system call. 
//----------------------------------------------------------------------
static int mmap (int id, void *address)
{
	int success = 0;
	struct map *mp = malloc (sizeof *mp);
	struct file_descriptor *f_d = get_file_desc (id);
	off_t len; 
	size_t offs;

	//check if mp is null or the address is null or the page offset 
	//of address is 0
	if (mp == NULL || address == NULL || pg_ofs (address) != 0){
		success = -1;
		return success;
	}//end of if	

	struct thread *cur = thread_current ();
	mp->map_id = cur -> next_value++;
	//acquire the file lock
	lock_acquire(&file_lock);
	//reopen the file
	mp->file = file_reopen (f_d->file);
	//release the file lock
	lock_release(&file_lock);
	//check if the file reopend is null is yes then free the map
	if (mp->file == NULL) 
	{
		free (mp);
		success = -1;
		return success;
	}//end of if
	 
	mp->num_of_pages = 0;	
	mp->start_addr = address;
	//insert the map in the current threads map list and map's elem
	list_push_front (&cur->map_list, &mp->elem);
	offs = 0;
	//acquire the file lock
	lock_acquire(&file_lock);
	//get the file length
	len = file_length (mp->file);
	//release the file lock
	lock_release(&file_lock);
	
	//check if length is greater than 0
	while (len > 0)
    {
		//allocate the page
		struct page *pg = allocation_of_page ((uint8_t *) address + offs, false);
		
		//check if the page allocated is null
		if (pg == NULL){
			//if page is null then unmap the map
			unmap (mp);
			success = -1;
			return success;
		}

		pg->file = mp->file;
		pg->private = false;
		pg->f_ofs = offs;

		//check if the length is greater than PGSIZE .Set the byts_rw_f 
		//accordingly
		if(len >= PGSIZE){
			pg->byts_rw_f = PGSIZE;
		}
		else{
			pg->byts_rw_f = len;
		}
		
		//update the length and offset
		offs += pg->byts_rw_f;
		len -= pg->byts_rw_f;
		//update the number of pages mapped in the map
		mp->num_of_pages = mp->num_of_pages + 1;
    }
  //return the map id
  return mp->map_id;
}// end of mmap

// Munmap system call. 
//----------------------------------------------------------------------
static int munmap (int mapping) 
{
	int success = 0;
	struct map *mp=get_map (mapping);
	if(mp == NULL){
		success = -1;
		return success;
	}//end of if
	
	unmap(mp);
	return success;
}// end of Mummap


//----------------------------------------------------------------------
/* this function is called by thread_exit() function to make sure that
   all the files are closed before the thread exits.Also if any of them 
   is open then this function will close them.And also unmap all the 
   map_list */
//$$----------------------------------------------------------------$$
void syscall_exit (void) 
{	
	struct list_elem *nxt;
	struct list_elem *ele;
	struct list_elem *e;
	struct thread *cur = thread_current (); 
	//close all the open files
	  for (ele = list_begin (&cur->file_descs);
		   ele != list_end (&cur->file_descs); 
		   ele = nxt){
		  struct file_descriptor *f_d;
		  //get the next entry
		  f_d = list_entry (ele, struct file_descriptor, elem);
		  nxt = list_next (ele);
		  lock_acquire(&file_lock);
		  //close the file
		  file_close (f_d->file);
		  lock_release(&file_lock);
		  // free the f_d
		  free (f_d);
		}// end of for
		
    //unmap all the map that are present in the current thread's map list
	  for (e = list_begin (&cur->map_list); 
			e != list_end (&cur->map_list);
			e = nxt){
			//get the next entry
			struct map *mp = list_entry (e, struct map, elem);
			nxt = list_next (e);
			//unmap the current map
			unmap (mp);
		}// end of for
}// end of syscall_exit
//----------------------------------------------------------------------