#ifndef LIBRESSL_PIPE
#define LIBRESSL_PIPE

#include "../test.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "ssl_locl.h"
#include <openssl/sgxbridge.h>

#define PRIVATE_KEY_FILE_SIZE 1733
#define NAME_BUF_SIZE 256
#define MAX_COMMANDS 64

#define RB_MODE_RD 0
#define RB_MODE_WR 1

typedef struct
{
  void (*callback)(int, char*);
  char* name;
} cmd_t;

typedef struct
{
  char* client_random;
  char* server_random;
  unsigned char master_key[SSL3_MASTER_SECRET_SIZE];
  unsigned char premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
  long algo;
} session_ctrl_t;

// prototypes
void open_pipes();
void load_pKey_and_cert_to_ssl_ctx();
void register_command(char* name, void (*callback)(int, char*));
void register_commands();
void check_commands(int cmd_len, char* cmd, int data_len, char* data);
void run_command_loop();

// TODO: write a macro for commands
void cmd_sess_id(int data_len, char* data);
void cmd_clnt_rand(int data_len, char* data);
void cmd_srv_rand(int data_len, char* data);
void cmd_algo(int data_len, char* data);
void cmd_premaster(int data_len, char* data);
void cmd_master_sec(int data_len, char* data);
void cmd_rsa_sign(int data_len, char* data);
void cmd_rsa_sign_sig_alg(int data_len, char* data);

extern int cmd_counter;
extern EVP_PKEY* private_key;
extern RSA* rsa;
extern SSL_CTX* ctx;
extern SSL_CIPHER new_cipher;
extern cmd_t _commands[MAX_COMMANDS];
extern session_ctrl_t session_ctrl;
extern char priv_key_file[];
extern char cert_file[];
#endif