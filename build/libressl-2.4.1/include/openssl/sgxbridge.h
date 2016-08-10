#ifndef _SGXBRIDGE_H_
#define _SGXBRIDGE_H_

#include <openssl/ssl.h>

#define CMD_MAX_BUF_SIZE 1024

#define CMD_SESS_ID 			0x00
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
#define CMD_ENCRYPT_RECORD    0x0C

#define NAME_BUF_SIZE 256
#define ENCODED_POINT_LEN_MAX 256

int sgxbridge_init();
int opensgx_pipe_init(int flag_dir);
int opensgx_pipe_open(char* unique_id, int is_write, int flag_dir);
void sgxbridge_pipe_read(int len, unsigned char* data);
void sgxbridge_pipe_write(unsigned char* data, int len);
void sgxbridge_pipe_write_cmd(int cmd, int len, unsigned char* data);
void print_hex(unsigned char* buf, int len);
void sgxbridge_generate_server_random(void* buf, int nbytes);
int sgxbridge_get_master_secret(unsigned char* buf);
void sgxbridge_rsa_sign_md(unsigned char* ip_md, int md_size,
                           unsigned char* op_sig, int* sig_size);
int sgxbridge_fetch_operation(int* cmd, int* data_len, unsigned char* data);
void sgxbridge_ecdhe_get_public_param(unsigned char* curve_id, int c_size, 
				      unsigned char* out, int* size);
void sgxbridge_ecdhe_generate_pre_master_key(unsigned char* client_pub, int k_size);

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
  SSL_CIPHER s_cipher;
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
  unsigned char ad[13];
  unsigned char nonce[16];
  unsigned char out_data[256];
  unsigned char data_record[256];
  unsigned int nonce_used;
  unsigned int eiv_length;
  unsigned int record_length;
} app_data_encrypt;


typedef struct
{
  unsigned char data[256];    /* pointer to the record data */
  unsigned char input[256];   /* where the decode bytes are */
  unsigned char seq_num[8]; /* sequence number, needed by DTLS1 */
  unsigned char write_seq_num[8];
  unsigned int type;               /* type of record */
  unsigned int length;    /* How many bytes available */
  unsigned int off;       /* read/write offset into 'buf' */
  unsigned long epoch;    /* epoch number, needed by DTLS1 */
} evp_ssl_record;
#endif /* _SGXBRIDGE_H_ */
