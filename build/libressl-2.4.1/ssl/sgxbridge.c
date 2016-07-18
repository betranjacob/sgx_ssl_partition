#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/sgxbridge.h>

#define RB_MODE_RD 0
#define RB_MODE_WR 1


char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;


int fd_sgx_ngx = -1;
int fd_ngx_sgx = -1;


int
opensgx_pipe_init(int flag_dir)
{
    int ret;

    if(flag_dir == 0)
        ret = mkdir(TMP_DIRECTORY_CONF, 0770);
    else if(flag_dir == 1)
        ret = mkdir(TMP_DIRECTORY_RUN, 0770);

    if(ret == -1)
    {
        if(errno != EEXIST) {
            puts("Fail to mkdir");
            return -1;
        }
    }
    return 0;
}

int
opensgx_pipe_open(char *unique_id, int is_write, int flag_dir)
{
    char name_buf[NAME_BUF_SIZE];

    if (flag_dir == 0) {
        strcpy(name_buf, TMP_DIRECTORY_CONF);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }
    else if (flag_dir == 1) {
        strcpy(name_buf, TMP_DIRECTORY_RUN);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }

    int ret = mknod(name_buf, S_IFIFO | 0770, 0);
    if(ret == -1)
    {
        if(errno != EEXIST) {
            puts("Fail to mknod");
            return -1;
        }
    }

    int flag = O_ASYNC;
    if(is_write)
        flag |= O_WRONLY;
    else
        flag |= O_RDONLY;

    int fd = open(name_buf, flag);

    if(fd == -1)
    {
        puts("Fail to open");
        return -1;
    }

    return fd;
}

void
sgxbridge_pipe_read(int len, char* data)
{

}

void
sgxbridge_pipe_write(char* cmd, int len, char* data)
{
    printf("sgxbridge_pipe_write, cmd: %s, len: %d\n", cmd, len);
    print_hex(data, len);
    // printf("%s\n", data);
    int cmd_len = strlen(cmd);

    write(fd_ngx_sgx, &cmd_len, sizeof(int));
    write(fd_ngx_sgx, cmd, cmd_len+1);

    write(fd_ngx_sgx, &len, sizeof(int));
    write(fd_ngx_sgx, data, len+1);
}

int
sgxbridge_init()
{
    if(opensgx_pipe_init(0) < 0) {
        // ngx_ssl_error(NGX_LOG_ALERT, log, 0, "pipe_init() failed");
        // return NGX_ERROR;
        return -1;
    }

    if((fd_sgx_ngx = opensgx_pipe_open("sgx_read", RB_MODE_RD, 0)) < 0) {
        // ngx_ssl_error(NGX_LOG_ALERT, log, 0, "pipe_open() failed");
        // return NGX_ERROR;
        return -1;
    }

    if((fd_ngx_sgx = opensgx_pipe_open("sgx_write", RB_MODE_WR, 0)) < 0) {
        // ngx_ssl_error(NGX_LOG_ALERT, log, 0, "pipe_open() failed");
        // return NGX_ERROR;
        return -1;
    }
    
    return 0;
}

void
print_hex(unsigned char *buf, int len)
{
    int cnt;
    for (cnt = 0; cnt < len; cnt++)
    {
        printf("%02X", buf[cnt]);
    }
    printf("\n");
}

void
sgxbridge_generate_server_random(void* buf, int nbytes) {
    printf("generate_server_random\n");

    sgxbridge_pipe_write(CMD_SRV_RAND, sizeof(int), &nbytes);
    read(fd_sgx_ngx, buf, nbytes);

    printf("server_random:\n");
    print_hex((unsigned char*) buf, nbytes);
}

int
sgxbridge_get_master_secret(unsigned char *buf) {
    sgxbridge_pipe_write(CMD_MASTER_SEC, 1, "m");
    read(fd_sgx_ngx, buf, SSL3_MASTER_SECRET_SIZE);

    return SSL3_MASTER_SECRET_SIZE;
}
