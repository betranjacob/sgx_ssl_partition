#ifndef _SGXBRIDGE_H_
#define _SGXBRIDGE_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>
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
#define CMD_SGX_SEAL           	        0x0F

#define NAME_BUF_SIZE 256
#define ENCODED_POINT_LEN_MAX 256

int sgxbridge_init();
int opensgx_pipe_init(int flag_dir);
int opensgx_pipe_open(char* unique_id, int is_write, int flag_dir);
void sgxbridge_pipe_read(int len, unsigned char* data);
void sgxbridge_pipe_write(unsigned char* data, int len);
void sgxbridge_pipe_write_cmd(SSL* s, int cmd, int len, unsigned char* data);
void sgxbridge_pipe_write_cmd_remove_session(unsigned char* session_id);
void print_hex(unsigned char* buf, int len);
void sgxbridge_generate_server_random(SSL* s, void* buf, int nbytes);
int sgxbridge_get_master_secret(SSL* s, unsigned char* buf);
void sgxbridge_rsa_sign_md(SSL* s, unsigned char* ip_md, int md_size,
    unsigned char* op_sig, int* sig_size);
int sgxbridge_fetch_operation(int* cmd, int* data_len, unsigned char* data);
void sgxbridge_ecdhe_get_public_param(SSL* s, unsigned char* curve_id,
    int c_size, unsigned char* out, int* size);
void sgxbridge_ecdhe_generate_pre_master_key(SSL* s, unsigned char* client_pub,
    int k_size);

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
  char data[CMD_MAX_BUF_SIZE];
} cmd_pkt_t;

typedef struct
{
  unsigned long cipher_id;
  int version;
  int mac_flags;
  /* s->method->ssl3_enc->enc_flags */
  unsigned int enc_flags;
  
  /* s->s3->tmp.new_sym_enc */
  EVP_CIPHER new_sym_enc;
  /* s->s3->tmp.new_hash; */
  int mac_sent;
  EVP_MD new_hash;
  /* s->s3->tmp.new_mac_pkey_type; */
  int new_mac_pkey_type;
  /* s->s3->tmp.new_mac_secret_size */
  int new_mac_secret_size;
  /* s->s3->tmp.new_aead */
  int aead_sent;
  EVP_AEAD new_aead;

  SSL_CIPHER new_cipher;

} sgx_change_cipher_st;

typedef struct
{ 
  size_t buf_len;
  unsigned char ad[13];
  unsigned char nonce[16];
  unsigned int nonce_used;
  size_t eivlen;
} sgx_tls1_enc_st;
#endif /* _SGXBRIDGE_H_ */
