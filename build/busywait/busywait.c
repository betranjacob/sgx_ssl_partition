#include <stdio.h>
#include <stdint.h>

#define SGX_DELAY 1000000


ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __real_read(int fd, void *buf, size_t count);

static inline uint64_t RDTSC()
{
  unsigned int hi, lo;
  __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
  return ((uint64_t)hi << 32) | lo;
}

void busywait(){

    uint64_t starttime, endtime;
    starttime = RDTSC();
    endtime = starttime + SGX_DELAY;

    printf("BUSYWAIT START %lu\n",starttime);
    while(endtime > RDTSC()){

    }
    printf("BUSYWAIT END   %lu\n",RDTSC());
}

ssize_t __wrap_write(int fd, const void *buf, size_t count){
  busywait();
  return __real_write(fd,buf,count);
}

ssize_t __wrap_read(int fd, void *buf, size_t count){
  busywait();
  return __real_read(fd,buf,count);
}
