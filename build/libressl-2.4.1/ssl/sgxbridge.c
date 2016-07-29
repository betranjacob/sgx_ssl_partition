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
char TMP_FILE_NUMBER_FMT[] = "/pipe_";

int fd_sgx_ssl = -1;
int fd_ssl_sgx = -1;

int
opensgx_pipe_init(int flag_dir)
{
  int ret;

  if (flag_dir == 0)
    ret = mkdir(TMP_DIRECTORY_CONF, 0770);
  else if (flag_dir == 1)
    ret = mkdir(TMP_DIRECTORY_RUN, 0770);

  if (ret == -1) {
    if (errno != EEXIST) {
      fprintf(stderr, "Fail to mkdir");
      return -1;
    }
  }
  return 0;
}

int
opensgx_pipe_open(char* unique_id, int is_write, int flag_dir)
{
  char name_buf[NAME_BUF_SIZE];

  if (flag_dir == 0) {
    strcpy(name_buf, TMP_DIRECTORY_CONF);
    strcpy(name_buf + strlen(name_buf), TMP_FILE_NUMBER_FMT);
    strcpy(name_buf + strlen(name_buf), unique_id);
  } else if (flag_dir == 1) {
    strcpy(name_buf, TMP_DIRECTORY_RUN);
    strcpy(name_buf + strlen(name_buf), TMP_FILE_NUMBER_FMT);
    strcpy(name_buf + strlen(name_buf), unique_id);
  }

  int ret = mknod(name_buf, S_IFIFO | 0770, 0);
  if (ret == -1) {
    if (errno != EEXIST) {
      fprintf(stderr, "Fail to mknod");
      return -1;
    }
  }

  int flag = O_ASYNC;
  if (is_write)
    flag |= O_WRONLY;
  else
    flag |= O_RDONLY;

  int fd = open(name_buf, flag);

  if (fd == -1) {
    fprintf(stderr, "Fail to open()");
    return -1;
  }

  return fd;
}

void
sgxbridge_pipe_read(int len, char* data)
{
  int fd = fd_sgx_ssl;

#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  read(fd, data, len);
}

void
sgxbridge_pipe_write(char* data, int len)
{
  int fd = fd_ssl_sgx;

#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  write(fd, data, len);
}

void
sgxbridge_pipe_write_cmd(int cmd, int len, char* data)
{
  int fd = fd_ssl_sgx;
  cmd_pkt_t cmd_pkt;
#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  printf("sgxbridge_pipe_write, cmd: %d, len: %d\n", cmd, len);
  print_hex(data, len);
  cmd_pkt.cmd = cmd;
  cmd_pkt.data_len = len;
  memcpy(cmd_pkt.data, data, CMD_MAX_BUF_SIZE);
  write(fd, &cmd_pkt, sizeof(cmd_pkt));
}

int
sgxbridge_init()
{
  // default for ssl library
  int mode_sgx_ssl = RB_MODE_RD;
  int mode_ssl_sgx = RB_MODE_WR;

#ifdef SGX_ENCLAVE
  mode_sgx_ssl = RB_MODE_WR;
  mode_ssl_sgx = RB_MODE_RD;
#endif

  if (opensgx_pipe_init(0) < 0) {
    fprintf(stderr, "%s - %s Pipe Init() failed \n", __FILE__, __func__);
    return -1;
  }

  if ((fd_sgx_ssl = opensgx_pipe_open("sgx_ssl", mode_sgx_ssl, 0)) < 0) {
    fprintf(stderr, "%s - %s Read Pipe Open() failed \n", __FILE__, __func__);
    return -1;
  }

  if ((fd_ssl_sgx = opensgx_pipe_open("ssl_sgx", mode_ssl_sgx, 0)) < 0) {
    fprintf(stderr, "%s - %s Write Pipe Open() failed \n", __FILE__, __func__);
    return -1;
  }

  return 0;
}

int
sgxbridge_fetch_operation(int* cmd, int* data_len, char* data)
{
  int fd = fd_sgx_ssl;
  cmd_pkt_t cmd_pkt;
#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  if (read(fd, &cmd_pkt, sizeof(cmd_pkt_t)) > 0) {
    *cmd = cmd_pkt.cmd;
    *data_len = cmd_pkt.data_len;
    memcpy(data, cmd_pkt.data, CMD_MAX_BUF_SIZE);
    printf("fetch_operation, cmd: %d, len: %d\n", cmd, *data_len);
    print_hex(data, *data_len);
    return 1;
  }
  return 0;
}

void
print_hex(unsigned char* buf, int len)
{
  int cnt;
  for (cnt = 0; cnt < len; cnt++) {
    printf("%02X", buf[cnt]);
  }
  printf("\n\r");
  fflush(stdout);
}

void
sgxbridge_generate_server_random(void* buf, int nbytes)
{
  printf("generate_server_random\n");

  sgxbridge_pipe_write_cmd(CMD_SRV_RAND, sizeof(int), &nbytes);
  read(fd_sgx_ssl, buf, nbytes);

  printf("server_random:\n");
  print_hex((unsigned char*)buf, nbytes);
}

int
sgxbridge_get_master_secret(unsigned char* buf)
{
  sgxbridge_pipe_write_cmd(CMD_MASTER_SEC, 1, "m");
  read(fd_sgx_ssl, buf, SSL3_MASTER_SECRET_SIZE);

  return SSL3_MASTER_SECRET_SIZE;
}

void
sgxbridge_rsa_sign_md(unsigned char* ip_md, int md_size, unsigned char* op_sig,
                      int* sig_size)
{
  sgxbridge_pipe_write_cmd(CMD_RSA_SIGN, md_size, ip_md);

  read(fd_sgx_ssl, sig_size, sizeof(int));
  read(fd_sgx_ssl, op_sig, *sig_size);
}

void
sgxbridge_rsa_sign_sig_algo_ex(unsigned char* ip_md, int md_size,
                               unsigned char* op_sig, int* sig_size)
{
  sgxbridge_pipe_write_cmd(CMD_RSA_SIGN_SIG_ALG, md_size, ip_md);

  read(fd_sgx_ssl, sig_size, sizeof(int));
  read(fd_sgx_ssl, op_sig, *sig_size);
}
