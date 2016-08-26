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
  void (*callback)(cmd_pkt_t, unsigned char*);
  int cmd_num;
} cmd_t;

typedef struct
{
  unsigned short int type;
  unsigned char id[SGX_SESSION_ID_LENGTH];
  int premaster_secret_length;
  unsigned char premaster_secret[SSL_MAX_PRE_MASTER_KEY_LENGTH];

  EC_KEY *ecdh;

  SSL *s;
} SGX_SESSION;

DECLARE_LHASH_OF(SGX_SESSION);

// prototypes
void open_pipes();
void load_pKey_and_cert_to_ssl_ctx();
void register_command(int cmd, void (*callback)(cmd_pkt_t, unsigned char*));
void register_commands();
void check_commands(cmd_pkt_t cmd_pkt, unsigned char* data);
void init_session(SGX_SESSION *sgx_s);
void run_command_loop();

// TODO: write a macro for commands
void cmd_clnt_rand(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_srv_rand(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_premaster(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_master_sec(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_rsa_sign(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_rsa_sign_sig_alg(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_ecdhe_get_public_param(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_ecdhe_generate_pre_master(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_ssl_handshake_done(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_ssl_session_remove(cmd_pkt_t cmd_pkt, unsigned char* data);

void cmd_key_block(cmd_pkt_t cmd_pkt, unsigned char *data);
void cmd_final_finish_mac(cmd_pkt_t cmd_pkt, unsigned char *data);
void cmd_change_cipher_state(cmd_pkt_t cmd_pkt, unsigned char* data);
void cmd_sgx_tls1_enc(cmd_pkt_t cmd_pkt, unsigned char *data);

extern int cmd_counter;
extern EVP_PKEY* private_key;
extern RSA* rsa;
extern SSL_CTX* ctx;
extern cmd_t _commands[MAX_COMMANDS];
extern char priv_key_file[];
extern char cert_file[];
#endif
