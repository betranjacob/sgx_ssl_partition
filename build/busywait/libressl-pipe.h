#ifndef LIBRESSL_PIPE
#define LIBRESSL_PIPE

#include "../test.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "ssl_locl.h"
#include <openssl/sgxbridge.h>
#include <openssl/lhash.h>
#include <openssl/md5.h>

#define PRIVATE_KEY_FILE_SIZE 1733
#define SSL_MAX_PRE_MASTER_KEY_LENGTH 256
#define NAME_BUF_SIZE 256
#define MAX_COMMANDS 64

#define RB_MODE_RD 0
#define RB_MODE_WR 1

#define SGX_SESSION_TYPE 0
#define SSL_SESSION_TYPE 1

typedef struct
{
  void (*callback)(int, unsigned char*);
  int cmd_num;
} cmd_t;

typedef struct
{
  unsigned short int type;
  // unsigned char id[SGX_SESSION_ID_LENGTH];
  unsigned char id[SSL_MAX_SSL_SESSION_ID_LENGTH];

  unsigned char* client_random;
  unsigned char* server_random;
  unsigned char master_key[SSL3_MASTER_SECRET_SIZE];
  int premaster_secret_length;
  unsigned char premaster_secret[SSL_MAX_PRE_MASTER_KEY_LENGTH];
  long algo;

  EC_KEY *ecdh;

} SGX_SESSION;

DECLARE_LHASH_OF(SGX_SESSION);

// prototypes
void open_pipes();
void load_pKey_and_cert_to_ssl_ctx();
void register_command(int cmd, void (*callback)(int, unsigned char*));
void register_commands();
void check_commands(int cmd, int data_len, unsigned char* data);
void init_session(SGX_SESSION *sgx_s);
void run_command_loop();

// TODO: write a macro for commands
void cmd_clnt_rand(int data_len, unsigned char* data);
void cmd_srv_rand(int data_len, unsigned char* data);
void cmd_premaster(int data_len, unsigned char* data);
void cmd_master_sec(int data_len, unsigned char* data);
void cmd_rsa_sign(int data_len, unsigned char* data);
void cmd_rsa_sign_sig_alg(int data_len, unsigned char* data);
void cmd_key_block(int data_len, unsigned char *data);
void cmd_final_finish_mac(int data_len, unsigned char *data);
void cmd_ecdhe_get_public_param(int data_len, unsigned char* data);
void cmd_ecdhe_generate_pre_master_key(int data_len, unsigned char* data);
void cmd_ssl_handshake_done(int data_len, unsigned char* data);
void cmd_ssl_session_remove(int data_len, unsigned char* data);

extern int cmd_counter;
extern EVP_PKEY* private_key;
extern RSA* rsa;
extern SSL_CTX* ctx;
extern cmd_t _commands[MAX_COMMANDS];
extern char priv_key_file[];
extern char cert_file[];
#endif
