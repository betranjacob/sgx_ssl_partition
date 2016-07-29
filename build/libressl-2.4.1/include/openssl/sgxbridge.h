#ifndef _SGXBRIDGE_H_
#define _SGXBRIDGE_H_

#include <openssl/ssl.h>

#define CMD_MAX_BUF_SIZE 1024

#define CMD_SESS_ID 0
#define CMD_CLNT_RAND 1
#define CMD_SRV_RAND 2
#define CMD_PREMASTER 3
#define CMD_MASTER_SEC 4
#define CMD_RSA_SIGN 6
#define CMD_RSA_SIGN_SIG_ALG 7
#define CMD_KEY_BLOCK 8
#define CMD_FINAL_FINISH_MAC 9

#define NAME_BUF_SIZE 256

int sgxbridge_init();
int opensgx_pipe_init(int flag_dir);
int opensgx_pipe_open(char* unique_id, int is_write, int flag_dir);
void sgxbridge_pipe_read(int len, char* data);
void sgxbridge_pipe_write(char* data, int len);
void sgxbridge_pipe_write_cmd(int cmd, int len, char* data);
void print_hex(unsigned char* buf, int len);
void sgxbridge_generate_server_random(void* buf, int nbytes);
int sgxbridge_get_master_secret(unsigned char* buf);
void sgxbridge_rsa_sign_md(unsigned char* ip_md, int md_size,
                           unsigned char* op_sig, int* sig_size);
int sgxbridge_fetch_operation(int* cmd, int* data_len, char* data);

typedef struct
{
  int key_block_len;
  long algo2;
  char str[16];
  int str_len;
  unsigned char buf[2 * EVP_MAX_MD_SIZE];
} sgxbridge_st;

typedef struct
{
 int cmd;
 int data_len;
 char data[CMD_MAX_BUF_SIZE];
}cmd_pkt_t;
#endif /* _SGXBRIDGE_H_ */
