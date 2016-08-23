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

#include "ssl_locl.h"

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

ssize_t
sgxbridge_pipe_read(size_t len, unsigned char* data)
{
  size_t num = 0, n;
  int fd = fd_sgx_ssl;

#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  while(num < len){
    if((n = read(fd, data + num, len - num)) < 0){
      fprintf(stderr, "SGX read() failed: %s\n", strerror(errno));

      return -1;
    } else {
      num += n;
      fprintf(stdout, "SGX read() %zu out of %zu bytes\n", num, len);
    }
  }

  return num;
}

ssize_t
sgxbridge_pipe_write(unsigned char* data, size_t len)
{
  size_t num = 0, n;
  int fd = fd_ssl_sgx;

#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  while(num < len){
    if((n = write(fd, data + num, len - num)) < 0){
      fprintf(stderr, "SGX write() failed: %s\n", strerror(errno));

      return -1;
    } else {
      num += n;
      fprintf(stdout, "SGX write() %zu out of %zu bytes\n", num, len);
    }
  }

  return num;
}

void
sgxbridge_pipe_write_cmd(SSL *s, int cmd, int len, unsigned char* data)
{
  int fd = fd_ssl_sgx;
  cmd_pkt_t cmd_pkt;
#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  printf("sgxbridge_pipe_write, cmd: %d, len: %d\n", cmd, len);
  print_hex_trim(data, len);

  cmd_pkt.cmd = cmd;
  memcpy(cmd_pkt.sgx_session_id, s->sgx_session_id, SGX_SESSION_ID_LENGTH);
  memcpy(cmd_pkt.ssl_session_id, s->session->session_id,
      SSL3_SSL_SESSION_ID_LENGTH);
  cmd_pkt.data_len = len;

  sgxbridge_pipe_write(&cmd_pkt, sizeof(cmd_pkt));
  sgxbridge_pipe_write(data, len);
}

void
sgxbridge_pipe_write_cmd_remove_session(unsigned char* session_id)
{
  cmd_pkt_t cmd_pkt;

  cmd_pkt.cmd = CMD_SSL_SESSION_REMOVE;
  cmd_pkt.data_len = 0;
  memcpy(cmd_pkt.ssl_session_id, session_id, SSL3_SSL_SESSION_ID_LENGTH);

  sgxbridge_pipe_write(&cmd_pkt, sizeof(cmd_pkt));
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
sgxbridge_fetch_operation(cmd_pkt_t *cmd_pkt)
{
  int fd = fd_sgx_ssl;
#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  if (sgxbridge_pipe_read(sizeof(cmd_pkt_t), cmd_pkt) > 0) {
    printf("fetch_operation, cmd: %d, len: %d\n",
        cmd_pkt->cmd, cmd_pkt->data_len);
    return 1;
  }
  return 0;
}

int
sgxbridge_fetch_data(unsigned char *data, size_t len)
{
  if (sgxbridge_pipe_read(len, data) > 0) {
    printf("SGX fetch data (%zu bytes)\n", len);
    print_hex_trim(data, len);
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
print_hex_trim(unsigned char *buf, int len){
  int cnt;

  for (cnt = 0; cnt < 128; cnt++) {
    if(cnt < 64) printf("%02X", buf[cnt]);
    else if(cnt == 64) printf("...");
    else printf("%02X", buf[len - 128 + cnt]);
  }
  printf("\n\r");
}

void
sgxbridge_generate_server_random(SSL *s, void* buf, int nbytes)
{
  printf("generate_server_random\n");

  sgxbridge_pipe_write_cmd(s,
      CMD_SRV_RAND,
      sizeof(int),
      (unsigned char *) &nbytes);

  sgxbridge_pipe_read(nbytes, buf);

  printf("server_random:\n");
  print_hex((unsigned char *) buf, nbytes);
}

int
sgxbridge_get_master_secret(SSL *s, unsigned char* buf)
{
  sgxbridge_pipe_write_cmd(s, CMD_MASTER_SEC, 1, "m");

  return SSL3_MASTER_SECRET_SIZE;
}

void
sgxbridge_rsa_sign_md(SSL *s,
    unsigned char* ip_md,
    int md_size,
    unsigned char* op_sig,
    int* sig_size)
{
  sgxbridge_pipe_write_cmd(s, CMD_RSA_SIGN, md_size, ip_md);

  sgxbridge_pipe_read(sizeof(int), sig_size);
  sgxbridge_pipe_read(*sig_size, op_sig);
}

void
sgxbridge_rsa_sign_sig_algo_ex(SSL *s,
    unsigned char* ip_md,
    int md_size,
    unsigned char* op_sig,
    int* sig_size)
{
  sgxbridge_pipe_write_cmd(s, CMD_RSA_SIGN_SIG_ALG, md_size, ip_md);

  sgxbridge_pipe_read(sizeof(int), sig_size);
  sgxbridge_pipe_read(*sig_size, op_sig);
}


void sgxbridge_ecdhe_get_public_param(SSL *s,
    unsigned char* curve_id,
    int c_size,
    unsigned char* out,
    int* size)
{
    sgxbridge_pipe_write_cmd(s, CMD_GET_ECDHE_PUBLIC_PARAM, c_size, curve_id);

    sgxbridge_pipe_read(sizeof(int), size);
    sgxbridge_pipe_read(*size, out);
}

void sgxbridge_ecdhe_generate_pre_master_key(SSL *s,
    unsigned char* client_pub,
    int k_size)
{
    sgxbridge_pipe_write_cmd(s, CMD_GET_ECDHE_PRE_MASTER, k_size, client_pub);

}

int
sgxbridge_change_cipher_state(SSL *s, int which)
{
  int sgx_status = 0;
  sgx_change_cipher_st sgx_change_cipher;

  sgx_change_cipher.which = which;
  sgx_change_cipher.cipher_id = s->session->cipher->id;
  sgx_change_cipher.version = s->version;
  sgx_change_cipher.mac_flags = s->mac_flags;
  sgx_change_cipher.enc_flags = s->method->ssl3_enc->enc_flags;

  sgxbridge_pipe_write_cmd(s, CMD_CHANGE_CIPHER_STATE,
      sizeof(sgx_change_cipher_st), (unsigned char *) &sgx_change_cipher);
  sgxbridge_pipe_read(sizeof(sgx_status), &sgx_status);

  return sgx_status;
}

int
sgxbridge_pipe_tls1_enc(SSL *s, size_t len, size_t eivlen,
    unsigned int nonce_used, unsigned char *nonce, unsigned char *ad,
    unsigned char *in, unsigned char *out, size_t *out_len, int send)
{
  int sgx_status = 0;
  unsigned char *tls1_enc_buf;
  sgx_tls1_enc_st sgx_tls1_enc;

  sgx_tls1_enc.len = len;
  sgx_tls1_enc.eivlen = eivlen;
  sgx_tls1_enc.nonce_used = nonce_used;
  sgx_tls1_enc.send = send;
  memcpy(sgx_tls1_enc.nonce, nonce, 16);
  memcpy(sgx_tls1_enc.ad, ad, 13);

  tls1_enc_buf = malloc(
      sizeof(sgx_tls1_enc_st) + len + eivlen);

  memcpy(tls1_enc_buf, &sgx_tls1_enc, sizeof(sgx_tls1_enc_st));

  // TODO: authentication tag is not passed for the decryption here
  memcpy(tls1_enc_buf + sizeof(sgx_tls1_enc_st), in, len + eivlen);

  sgxbridge_pipe_write_cmd(s, CMD_SGX_TLS1_ENC,
      sizeof(sgx_tls1_enc_st) + len + eivlen, tls1_enc_buf);
  sgxbridge_pipe_read(sizeof(size_t), out_len);
  sgxbridge_pipe_read(sizeof(int), &sgx_status);
  sgxbridge_pipe_read(*out_len + eivlen, out);

  return sgx_status;
}
