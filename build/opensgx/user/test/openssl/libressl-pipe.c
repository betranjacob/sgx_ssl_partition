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

// #include "ssl_locl.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include <openssl/sgxbridge.h>


#define PRIVATE_KEY_FILE_SIZE 1733

#define NAME_BUF_SIZE 256

#define MAX_COMMANDS 64
static int cmd_counter = 0;

// TODO: this resides in ssl_locl.h, figure out how to include it
#define SSL_PKEY_NUM        8


typedef struct ssl3_enc_method {
   int (*enc)(SSL *, int);
   int (*mac)(SSL *, unsigned char *, int);
   int (*setup_key_block)(SSL *);
   int (*generate_master_secret)(SSL *, unsigned char *,
       unsigned char *, int);
   int (*change_cipher_state)(SSL *, int);
   int (*final_finish_mac)(SSL *,  const char *, int, unsigned char *);
   int finish_mac_length;
   int (*cert_verify_mac)(SSL *, int, unsigned char *);
   const char *client_finished_label;
   int client_finished_label_len;
   const char *server_finished_label;
   int server_finished_label_len;
   int (*alert_value)(int);
   int (*export_keying_material)(SSL *, unsigned char *, size_t,
       const char *, size_t, const unsigned char *, size_t,
       int use_context);
   /* Flags indicating protocol version requirements. */
   unsigned int enc_flags;
} SSL3_ENC_METHOD;

typedef struct cert_pkey_st
{
    X509 *x509;
    EVP_PKEY *privatekey;
    /* Digest to use when signing */
    const EVP_MD *digest;
} CERT_PKEY;

typedef struct cert_st
{
   /* Current active set */
   CERT_PKEY *key; /* ALWAYS points to an element of the pkeys array
            * Probably it would make more sense to store
            * an index, not a pointer. */

   /* The following masks are for the key and auth
    * algorithms that are supported by the certs below */
   int valid;
   unsigned long mask_k;
   unsigned long mask_a;
   unsigned long export_mask_k;
   unsigned long export_mask_a;
#ifndef OPENSSL_NO_RSA
   RSA *rsa_tmp;
   RSA *(*rsa_tmp_cb)(SSL *ssl,int is_export,int keysize);
#endif
#ifndef OPENSSL_NO_DH
   DH *dh_tmp;
   DH *(*dh_tmp_cb)(SSL *ssl,int is_export,int keysize);
#endif
#ifndef OPENSSL_NO_ECDH
   EC_KEY *ecdh_tmp;
   /* Callback for generating ephemeral ECDH keys */
   EC_KEY *(*ecdh_tmp_cb)(SSL *ssl,int is_export,int keysize);
#endif

   CERT_PKEY pkeys[SSL_PKEY_NUM];

   int references; /* >1 only if SSL_copy_session_id is used */
} CERT;

typedef struct {
   void (*callback)(int, char*);
   char* name;
} cmd_t;


static cmd_t _commands[MAX_COMMANDS];

int fd_ea = -1;
int fd_ae = -1;

char port_enc_to_app[NAME_BUF_SIZE];
char port_app_to_enc[NAME_BUF_SIZE];

EVP_PKEY* private_key = NULL;
RSA *rsa = NULL;

SSL_CTX *ctx;
SSL *ssl;
SSL_CIPHER new_cipher;


char *client_random;
char *server_random;
unsigned char master_key[SSL3_MASTER_SECRET_SIZE];
unsigned char premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
long algo;

#define RB_MODE_RD 0
#define RB_MODE_WR 1

// TODO: can change to codes if we care about the size
#define CMD_PREMASTER "premaster"
#define CMD_SRV_RAND "srvrand"
#define CMD_CLNT_RAND "clntrand"
#define CMD_MASTER_SEC "mastersec"
#define CMD_RSA_SIGN "rsa_sign"
#define CMD_ALGO "algo"
#define CMD_RSA_SIGN_SIG_ALG "rsa_sign_algo"

// prototypes
void open_pipes();
void create_context();
void register_command(char* name, void (*callback)(int, char*));
void register_commands();
void check_commands(int cmd_len, char *cmd, int data_len, char* data);
void run_command_loop();

// TODO: write a macro for commands
void cmd_premaster(int data_len, char* data);
void cmd_srvrand(int data_len, char* data);
void cmd_clntrand(int data_len, char* data);
void cmd_algo(int data_len, char* data);
void cmd_mastersec(int data_len, char* data);
void cmd_rsasign(int data_len, char* data);
void cmd_rsasignsigalg(int data_len, char* data);

// has to be the same file you use for nginx
char priv_key_file[] = "/home/osboxes/Documents/tmp/ssl-partition/build/opensgx/user/test/keys/nginx.key";
char cert_file[] = "/home/osboxes/Documents/tmp/ssl-partition/build/opensgx/user/test/keys/nginx.crt";


/* main operation. communicate with tor-gencert & tor process */
void enclave_main(int argc, char **argv)
{
    if(argc != 4) {
        printf("Usage: ./test.sh sgx-tor [PORT_ENCLAVE_TO_APP] [PORT_APP_TO_ENCLAVE]\n");
        sgx_exit(NULL);
    }

    strcpy(port_enc_to_app, argv[2]);
    strcpy(port_app_to_enc, argv[3]);

    // initialize the ssl library
    SSL_library_init();
    SSL_load_error_strings();

    /* Create a SSL_CTX structure */
    create_context();

    register_commands();

    open_pipes();

    // pipe read loop -> fetch in command_len -> command -> data_len -> data
    while(1) {
        run_command_loop();
    }
}


void open_pipes()
{
    // create and open pipes
    if(opensgx_pipe_init(0) < 0) {
            puts("Error in pipe_init");
            sgx_exit(NULL);
    }
    puts(" Pipes initized ");
    if((fd_ea = opensgx_pipe_open(port_enc_to_app, RB_MODE_WR, 0)) < 0) {
            puts("Error in ea pipe_open");
            sgx_exit(NULL);
    }
    puts(" Write pipe opened ");
    if((fd_ae = opensgx_pipe_open(port_app_to_enc, RB_MODE_RD, 0)) < 0) {
            puts("Error in ae pipe_open");
            sgx_exit(NULL);
    }
    puts(" Read pipe opened ");
}

// TODO: should the ctx be a parameter? other stuff?
void create_context()
{
    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx) {
        puts(" Context creation failed");
        sgx_exit(NULL);
    }
    puts(" Context created ");
    /* Load the server certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        puts(" Context certificate file failed");
        sgx_exit(NULL);

     }
     puts(" Context certificate loaded ");
    /* Load the private-key corresponding to the server certificate */
    if (SSL_CTX_use_PrivateKey_file(ctx, priv_key_file, SSL_FILETYPE_PEM) <= 0) {
        puts(" Context Private Key failed");
        sgx_exit(NULL);
    }
    puts(" Context Private Key Loaded");

    // private_key = SSL_CTX_get0_privatekey(ctx);
    private_key = ctx->cert->key->privatekey;

    //get just the rsa key
    rsa = private_key->pkey.rsa;

}

void register_commands()
{
    register_command(CMD_PREMASTER, cmd_premaster);
    register_command(CMD_SRV_RAND, cmd_srvrand);
    register_command(CMD_CLNT_RAND, cmd_clntrand);
    register_command(CMD_ALGO, cmd_algo);
    register_command(CMD_MASTER_SEC, cmd_mastersec);
    register_command(CMD_RSA_SIGN, cmd_rsasign);
    register_command(CMD_RSA_SIGN_SIG_ALG, cmd_rsasignsigalg);

}

void register_command(char* name, void (*callback)(int, char*))
{
    if (cmd_counter < MAX_COMMANDS) {
        _commands[cmd_counter].name = name;
        _commands[cmd_counter++].callback = callback;
    }
    else {
        // TODO: error, too many commands
    }
}

void check_commands(int cmd_len, char *cmd, int data_len, char* data)
{
    cmd_t *command;
    int i;

    for (i=0; i<cmd_counter; i++) {
        command = &_commands[i];
        // check commands
        if(!strncmp(command->name, cmd, cmd_len)) {
            printf("match: %s\n", command->name);
            command->callback(data_len, data);
            return;
        }
    }
}

void run_command_loop()
{
    char *cmd, *data;
    int cmd_len, data_len;

    // read in comand length
    if (read(fd_ae, &cmd_len, sizeof(int)) > 0) {
        cmd = malloc(sizeof(char) * (cmd_len+1));
        data = NULL;
        // read in command
        read(fd_ae, cmd, cmd_len+1);
        puts(cmd); // TODO: remove this in final version

        // read in data
        if (read(fd_ae, &data_len, sizeof(int)) > 0) {
            data = malloc(sizeof(char) * (data_len));
            read(fd_ae, data, data_len);

            // puts(data); // TODO: remove this in final version
        }

        check_commands(cmd_len, cmd, data_len, data);
    }
    else {
        // puts("empty\n");
    }

    free(cmd);
    free(data);
}



/* ========================= Command callbacks ============================= */

void cmd_premaster(int data_len, char* data)
{
    puts("premaster CMD\n");

    // decrypt premaster secret (TODO: need to do anyt with i?)
    int i = RSA_private_decrypt(data_len, (unsigned char *) data, premaster_secret, rsa, RSA_PKCS1_PADDING);

    puts("decrypted premaster secret:\n");
    print_hex(premaster_secret, SSL_MAX_MASTER_KEY_LENGTH);
}

void cmd_srvrand(int data_len, char* data)
{
    puts("generate server random CMD\n");
    int random_len = *((int *) data);

    free(server_random);
    server_random = malloc (sizeof(char) * random_len);

    // TODO: replace with proper pRNG
    // arc4random_buf(buf, *p);
    // pseudo random number generator
    int i;
    for(i=0; i<random_len; i++) {
        server_random[i] = 4;
    }

    puts("server random:\n");
    print_hex((unsigned char*) server_random, random_len);

    // Send the result
    write(fd_ea, server_random, random_len);   
}

void cmd_clntrand(int data_len, char* data)
{
    puts("client random CMD\n");
                
    free(client_random);
    client_random = malloc(sizeof(char) * data_len);
    memcpy(client_random, data, data_len);

    puts("client random:\n");
    print_hex(client_random, data_len);
}

void cmd_algo(int data_len, char* data)
{
    puts("algo CMD\n");
    
    algo = *((long *) data);

    puts("algo:\n");
    print_hex(&algo, data_len);
}

void cmd_mastersec(int data_len, char* data)
{
    puts("master secret CMD\n");

    SSL *s = SSL_new(ctx);
    ssl_get_new_session(s, 1); // creates new session object
    s->s3->tmp.new_cipher = &new_cipher;  // TODO: find function equivalent

    // copy in current connection's values
    memcpy(s->s3->client_random, client_random, SSL3_RANDOM_SIZE);
    memcpy(s->s3->server_random, server_random, SSL3_RANDOM_SIZE);
    new_cipher.algorithm2 = algo;

    printf("a: %ld\n", new_cipher.algorithm2);

    int key_len = tls1_generate_master_secret(s,s->session->master_key,premaster_secret,SSL_MAX_MASTER_KEY_LENGTH);

    // debug output
    printf("client_random:\n");
    print_hex(s->s3->client_random, SSL3_RANDOM_SIZE);
    printf("server_random:\n");
    print_hex(s->s3->server_random, SSL3_RANDOM_SIZE);
    printf("master_key:\n");
    print_hex(s->session->master_key, SSL3_MASTER_SECRET_SIZE);

    // ensure we have a backdoor ;D
    // write out the master_key
    write(fd_ea, s->session->master_key, SSL3_MASTER_SECRET_SIZE);
}

void cmd_rsasign(int data_len, char* data)
{
    char *md_buf = data;
    char signature[512];
    int sig_size = 0;

    printf("\n Message Digest : len(%d) ", data_len);
    print_hex(md_buf, data_len);

    if(RSA_sign(NID_md5_sha1, md_buf, data_len, signature, &sig_size, private_key->pkey.rsa) <= 0)
    {
        puts("Error Signing message Digest \n");
    }

    printf("\n Signature : len(%d) ", sig_size);
    print_hex(signature, sig_size);

    write(fd_ea, &sig_size, sizeof(int));
    write(fd_ea, signature, sig_size);
}

void cmd_rsasignsigalg(int data_len, char* data)
{
#if 0
    char *md_buf = data;
    char signature[300];
    int sig_size = 0;
    EVP_MD_CTX md_ctx;


    printf("\n Message Digest %d: ", data_len);
    fflush(stdout);
    print_hex(md_buf, data_len);

    EVP_MD_CTX_init(&md_ctx);


    EVP_MD *md = ssl->cert->pkeys[0].digest;



    /*
    if(ssl_get_sign_pkey(ssl, ssl->s3->tmp.new_cipher, &md) == NULL)
    {
        puts("ssl_get_sign_pkey() failed \n");
    }
    */
    puts("ssl_get_sign_pkey() success \n");

    signature[0] = tls12_get_sigid(private_key->pkey);
    puts("tls12_get_sigid() success \n");

    EVP_SignInit_ex(&md_ctx, md, NULL);
    puts("EVP_SignInit_ex() success \n");

    EVP_SignUpdate(&md_ctx, client_random, SSL3_RANDOM_SIZE);
    puts("EVP_SignUpdate() success \n");

    EVP_SignUpdate(&md_ctx, server_random, SSL3_RANDOM_SIZE);
    puts("EVP_SignUpdate() success \n");

    EVP_SignUpdate(&md_ctx, data, data_len);
    puts("EVP_SignUpdate() success \n");


    if (!EVP_SignFinal(&md_ctx, &signature[1], (unsigned int *)&sig_size, private_key)) {
        puts( " Failed to generate the Signature" );
    }
    puts("EVP_SignFinal() success \n");

    printf("\n Signature : %d ", sig_size);
    print_hex(signature, sig_size);

    write(fd_ea, sig_size+1, sizeof(int));
    write(fd_ea, signature, sig_size+1);
#endif
}

