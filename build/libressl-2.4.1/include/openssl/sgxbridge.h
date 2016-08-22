#ifndef _SGXBRIDGE_H_
#define _SGXBRIDGE_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include "../../crypto/evp/evp_locl.h"

#define CMD_MAX_BUF_SIZE 1024

#define CMD_CLNT_RAND 			0x01
#define CMD_SRV_RAND 			0x02
#define CMD_PREMASTER 			0x03
#define CMD_MASTER_SEC 			0x04
#define CMD_RSA_SIGN 			0x06
#define CMD_RSA_SIGN_SIG_ALG 		0x07
#define CMD_KEY_BLOCK 			0x08
#define CMD_FINAL_FINISH_MAC		0x09
#define CMD_GET_ECDHE_PUBLIC_PARAM 	0x0A
#define CMD_GET_ECDHE_PRE_MASTER   	0x0B
#define CMD_SSL_HANDSHAKE_DONE     	0x0C
#define CMD_SSL_SESSION_REMOVE   	0x0D
#define CMD_CHANGE_CIPHER_STATE   	0x0E
#define CMD_SGX_TLS1_ENC 	        0x0F

#define NAME_BUF_SIZE 256
#define ENCODED_POINT_LEN_MAX 256

typedef struct
{
  char encodedPoint[ENCODED_POINT_LEN_MAX];
  int encoded_length;
  int curve_id;
  int rsa_public_key_size;
} ecdhe_params;

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
  unsigned char ssl_session_id[SSL3_SSL_SESSION_ID_LENGTH];
  unsigned char sgx_session_id[SGX_SESSION_ID_LENGTH];
  char data[CMD_MAX_BUF_SIZE];
} cmd_pkt_t;

typedef struct
{
  int which;
  unsigned long cipher_id;
  int version;
  int mac_flags;
  unsigned int enc_flags;

} sgx_change_cipher_st;

typedef struct
{
  size_t len;
  size_t eivlen;
  unsigned int nonce_used;
  int send;
  unsigned char nonce[16];
  unsigned char ad[13];
} sgx_tls1_enc_st;

int sgxbridge_init();
int opensgx_pipe_init(int flag_dir);
int opensgx_pipe_open(char* unique_id, int is_write, int flag_dir);
ssize_t sgxbridge_pipe_read(size_t len, unsigned char* data);
void sgxbridge_pipe_write(unsigned char* data, int len);
void sgxbridge_pipe_write_cmd(SSL* s, int cmd, int len, unsigned char* data);
void sgxbridge_pipe_write_cmd_remove_session(unsigned char* session_id);
void print_hex(unsigned char* buf, int len);
void sgxbridge_generate_server_random(SSL* s, void* buf, int nbytes);
int sgxbridge_get_master_secret(SSL* s, unsigned char* buf);
void sgxbridge_rsa_sign_md(SSL* s, unsigned char* ip_md, int md_size,
    unsigned char* op_sig, int* sig_size);
int sgxbridge_fetch_operation(cmd_pkt_t *cmd_pkt, unsigned char* data);
void sgxbridge_ecdhe_get_public_param(SSL* s, unsigned char* curve_id,
    int c_size, unsigned char* out, int* size);
void sgxbridge_ecdhe_generate_pre_master_key(SSL* s, unsigned char* client_pub,
    int k_size);
int sgxbridge_change_cipher_state(SSL *s , int which);
int sgxbridge_pipe_tls1_enc(SSL *s, size_t len, size_t eivlen,
    unsigned int nonce_used, unsigned char *nonce, unsigned char *ad,
    unsigned char *in, unsigned char *out, size_t *out_len, int send);

#endif /* _SGXBRIDGE_H_ */
