#include "loader.h"

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;
void *file_content;
void *entry_address;
off_t filesize;
void *virtual_mem;
Elf32_Phdr *entry_segment;
int page_faults;
int tot_page_alloc;
double tot_internal_frag;

void handle_segv(int signo,siginfo_t *si, void *context) {
  if (signo == SIGSEGV) {
    // printf("Segmentation fault handled\n");
    // printf("si_signo: %d\n", si->si_signo);
    // printf("si_errno: %d\n", si->si_errno);
    // printf("si_code: %d\n", si->si_code);
    // printf("si_addr: %p\n", si->si_addr);
    page_faults++;


    


   // 2. Iterate through the PHDR table and find the section of PT_LOAD type that contains the address of the entrypoint method in fib.c
    int i = 0;
    Elf32_Word p_memsz = 0;
    size_t page_size = 4096; // 4KB,
    while (i < ehdr->e_phnum) {
      // printf("phdr[i].p_vaddr: 0x%08X\n", phdr[i].p_vaddr);
      // printf("si->si_addr: 0x%08X\n", (uintptr_t)si->si_addr);
     //   if ((uintptr_t)phdr[i].p_vaddr == (uintptr_t)si->si_addr) {
      p_memsz = phdr[i].p_memsz;
      uintptr_t sum = (uintptr_t)phdr[i].p_vaddr + p_memsz;
      if ((uintptr_t)si->si_addr >= (uintptr_t)phdr[i].p_vaddr && (uintptr_t)si->si_addr < sum) {
          entry_segment = &phdr[i];
          break;
      }
     //   }
        i++;
    }

    size_t aligned_memsz = (p_memsz + page_size - 1) & ~(page_size - 1);
    // printf("aligned_memsz: %zu\n", aligned_memsz);
    // printf("p_memsz: %u\n", p_memsz);
    // printf("page_size: %u\n", page_size);
    tot_page_alloc += aligned_memsz/4096;
    //double internal_fragmentation = (((double)(aligned_memsz-p_memsz))/(double)p_mems
    tot_internal_frag += ((double)(aligned_memsz-p_memsz))/1000;


    // 3. Allocate memory of the size "p_memsz" using mmap function and then copy the segment content
    virtual_mem= mmap((void *)phdr[i].p_vaddr, aligned_memsz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE,0,0); //HOPEFULLY
    if (virtual_mem == MAP_FAILED) {
      perror("mmap");
      munmap(file_content, filesize);
      close(fd);
    }

    size_t offset = 0;
    while (offset < entry_segment->p_memsz) {
        ((char *)virtual_mem)[offset] = ((char *)file_content)[entry_segment->p_offset + offset];
        offset++;
    }


    // 4. Navigate to the entrypoint address into the segment loaded in the memory in above step
    uintptr_t entry_offset = ehdr->e_entry - entry_segment->p_vaddr;
    void *entry_address = (char *)virtual_mem + entry_offset;




  }
}

/*
 * release memory and other cleanups
 */
void loader_cleanup() {
  munmap(file_content, filesize);
  close(fd);
}

/*
 * Load and run the ELF executable file
 */
void load_and_run_elf(char** argv) {
  fd = open(argv[1], O_RDONLY);
  filesize = lseek(fd, 0, SEEK_END);
  file_content = malloc(filesize);

  lseek(fd, 0, SEEK_SET);
  read(fd, file_content, filesize);
  
  // 1. Load entire binary content into the memory from the ELF file.
  ehdr=(Elf32_Ehdr*)(file_content);
  phdr=(Elf32_Phdr*)(file_content + ehdr->e_phoff);
  Elf32_Phdr *entry_segment = NULL;

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO; // To receive additional info in siginfo_t
  sa.sa_sigaction = handle_segv; // Use sa_sigaction for the handler
  sigaction(SIGSEGV, &sa, NULL);


  


  // 5. Typecast the address to that of function pointer matching "_start" method in fib.c.
  int (*_start)() = (int (*)())ehdr->e_entry;


  // 6. Call the "_start" method and print the value returned from the "_start"
  int result = _start();
  // printf("Check1 pass\n");
  printf("User _start return value = %d\n",result);
}

int main(int argc, char** argv) 
{
  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \n",argv[0]);
    exit(1);
  }
  page_faults = 0;
  tot_page_alloc = 0;
  tot_internal_frag = 0;
  
  // 1. carry out necessary checks on the input ELF file
  // 2. passing it to the loader for carrying out the loading/execution
  load_and_run_elf(argv);
  // 3. invoke the cleanup routine inside the loader 
  printf("Total no. of page faults : %d\n",page_faults); 
  printf("Total page allocations : %d\n",tot_page_alloc);
  printf("Total internal fragmentation : %.3lf KB\n ",tot_internal_frag);
  loader_cleanup();
  return 0;
}
