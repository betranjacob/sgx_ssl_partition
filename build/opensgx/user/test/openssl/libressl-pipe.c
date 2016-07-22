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

// TODO: this resides in ssl_locl.h, figure out how to include it
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



EVP_PKEY* private_key = NULL;
RSA *rsa = NULL;

BIGNUM *bn = NULL;

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

// has to be the same file you use for nginx
char priv_key_file[] = "/etc/nginx/ssl/key.pem";
char cert_file[] = "/etc/nginx/ssl/cert.pem";

// char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
// char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
// char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
// int NAME_BUF_SIZE = 256;

SSL ssl_obj;
SSL3_STATE s3;
SSL_SESSION session;
SSL_CIPHER new_cipher;
SSL_CTX *ctx;

// static int pipe_init(int flag_dir)
// {
// 	int ret;

// 	if(flag_dir == 0)
// 		ret = mkdir(TMP_DIRECTORY_CONF, 0770);
// 	else if(flag_dir == 1)
// 		ret = mkdir(TMP_DIRECTORY_RUN, 0770);

// 	if(ret == -1)
// 	{
// 		if(errno != EEXIST) {
//                 puts("Fail to mkdir");
//                 return -1;
//         }
// 	}
// 	return 0;
// }

// static int pipe_open(char *unique_id, int is_write, int flag_dir)
// {
// 	char name_buf[NAME_BUF_SIZE];

//     if (flag_dir == 0) {
//         strcpy(name_buf, TMP_DIRECTORY_CONF);
//         strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
//         strcpy(name_buf+strlen(name_buf), unique_id);
//     }
//     else if (flag_dir == 1) {
//         strcpy(name_buf, TMP_DIRECTORY_RUN);
//         strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
//         strcpy(name_buf+strlen(name_buf), unique_id);
//     }

//     unlink(name_buf);
// 	int ret = mknod(name_buf, S_IFIFO | 0770, 0);
// 	if(ret == -1)
// 	{
//         if(errno != EEXIST) {
//             puts("Fail to mknod");
//             return -1;
//         }
// 	}

//     int flag = O_ASYNC;
// 	if(is_write)
// 		flag |= O_WRONLY;
// 	else
// 		flag |= O_RDONLY;

// 	int fd = open(name_buf, flag);

//     if(fd == -1)
//     {
//         puts("Fail to open");
//         return -1;
//     }

//     return fd;
// }

EVP_PKEY* read_private_key(char *key_file) {
    EVP_PKEY *pPrivKey;

    // open private key file
    int pFile = open(key_file, O_RDONLY);
    if(!pFile)
    {
        puts("Cannot open private key file.\n");
        // handle_openssl_error();
        return NULL;
    }

    // allcoate buffer private key file will be read to
    char *key = malloc(PRIVATE_KEY_FILE_SIZE); 
    
    // read in the key file
    read(pFile, key, PRIVATE_KEY_FILE_SIZE);

    // create new bio from the key memory
    // TODO: trying to create bio from file fails with segmentation fault
    BIO *bio_key = BIO_new_mem_buf(key, strlen(key));
    if(bio_key == NULL) {
        puts("key_bio creation failed.\n");
        return NULL;
    }

    // read in private key
    pPrivKey = PEM_read_bio_PrivateKey(bio_key, pPrivKey, NULL, NULL);;
    if(pPrivKey == NULL)
    {
        puts("Cannot read priate key.\n");
        return NULL;
    }

    // create bio to write to stdout
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // print out the private key
    // EVP_PKEY_print_private(bio_out,pPrivKey,0,NULL);

    // free memory
    BIO_free(bio_key);
    BIO_free(bio_out);
    free(key);

    // close key file
    close(pFile);

    return pPrivKey;
}

// thought printf doesnt work in an enclave..
// void
// print_hex(unsigned char* buf, int len)
// {
//     int cnt;
//     for (cnt = 0; cnt < len; cnt++)
//     {
//         printf("%02X", buf[cnt]);
//     }
//     printf("\n");
// }

// For simplicity, this function do simple operation.
// In the realistic scenario, key creation, signature generation and etc will be
// the possible example.
void do_secret(char *buf) 
{
    for(int i=0; i<strlen(buf); i++)
        buf[i]++;
}

/* main operation. communicate with tor-gencert & tor process */
void enclave_main(int argc, char **argv)
{
    int fd_ea = -1;
    int fd_ae = -1;

    int cmd_len;
    int data_len;

    char port_enc_to_app[NAME_BUF_SIZE];
    char port_app_to_enc[NAME_BUF_SIZE];

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
#if 0
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

    ssl = SSL_new(ctx);
	//private_key = ssl->cert->pkeys[0].privatekey;
    //private_key = SSL_CTX_get0_privatekey(ssl);

#else
    private_key = read_private_key(priv_key_file);
    if (private_key == NULL) {
    	puts("private key loading failed ");
        sgx_exit(NULL);
    }
    else {
        puts("private key loaded\n");
    }
#endif
    //get just the rsa key
    rsa = private_key->pkey.rsa;


    // create and open pipes
    if(opensgx_pipe_init(0) < 0) {
            puts("Error in pipe_init");
            sgx_exit(NULL);
    }

    if((fd_ea = opensgx_pipe_open(port_enc_to_app, RB_MODE_WR, 0)) < 0) {
            puts("Error in ea pipe_open");
            sgx_exit(NULL);
    }

    if((fd_ae = opensgx_pipe_open(port_app_to_enc, RB_MODE_RD, 0)) < 0) {
            puts("Error in ae pipe_open");
            sgx_exit(NULL);
    }

    // pipe read loop -> fetch in command_len -> command -> data_len -> data
    while(1) {
        // read in comand length
        if (read(fd_ae, &cmd_len, sizeof(int)) > 0) {
            char *cmd = malloc(sizeof(char) * (cmd_len+1));
            char *data = NULL;
            // read in command
            read(fd_ae, cmd, cmd_len+1);
            puts(cmd); // TODO: remove this in final version

            // read in data
            if (read(fd_ae, &data_len, sizeof(int)) > 0) {
                data = malloc(sizeof(char) * (data_len));
                read(fd_ae, data, data_len);

                // puts(data); // TODO: remove this in final version
            }

            // check commands
            if(!strncmp(cmd, CMD_PREMASTER, cmd_len)) {
                puts("premaster CMD\n");

                // decrypt premaster secret (TODO: need to do anyt with i?)
                int i = RSA_private_decrypt(data_len, (unsigned char *) data, premaster_secret, rsa, RSA_PKCS1_PADDING);

                puts("decrypted premaster secret:\n");
                print_hex(premaster_secret, SSL_MAX_MASTER_KEY_LENGTH);
            }
            else if(!strncmp(cmd, CMD_SRV_RAND, cmd_len)) {
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
            else if(!strncmp(cmd, CMD_CLNT_RAND, cmd_len)) {
                puts("client random CMD\n");
                
                free(client_random);
                client_random = malloc(sizeof(char) * data_len);
                memcpy(client_random, data, data_len);

                puts("client random:\n");
                print_hex(client_random, data_len);
            }
            else if(!strncmp(cmd, CMD_ALGO, cmd_len)) {
                puts("algo CMD\n");
                
                algo = *((long *) data);

                puts("algo:\n");
                print_hex(&algo, data_len);
            }
            else if(!strncmp(cmd, CMD_MASTER_SEC, cmd_len)) {
                puts("master secret CMD\n");

                SSL *s = &ssl_obj;
                s3.tmp.new_cipher = &new_cipher;
                s->s3 = &s3;
                s->session = &session;
                s->method = SSLv23_method();              

                // copy in current connection's values
                memcpy(s->s3->client_random, client_random, SSL3_RANDOM_SIZE);
                memcpy(s->s3->server_random, server_random, SSL3_RANDOM_SIZE);
                new_cipher.algorithm2 = algo;

                // printf("a: %ld\n", new_cipher.algorithm2);
    
                int key_len = tls1_generate_master_secret(s,master_key,premaster_secret,SSL_MAX_MASTER_KEY_LENGTH);

                // debug output
                printf(".client_random:\n");
                print_hex(s->s3->client_random, SSL3_RANDOM_SIZE);
                printf("server_random:\n");
                print_hex(s->s3->server_random, SSL3_RANDOM_SIZE);
                printf("master_key:\n");
                print_hex(s->session->master_key, SSL3_MASTER_SECRET_SIZE);

                // ensure we have a backdoor ;D
                // write out the master_key
                write(fd_ea, s->session->master_key, SSL3_MASTER_SECRET_SIZE);
            }
            else if(!strncmp(cmd, CMD_RSA_SIGN, cmd_len))
            {
            	char *md_buf = data;
            	char signature[512];
            	int sig_size = 0;

            	printf("\n Message Digest : len(%d) ", data_len);
            	fflush(stdout);
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
            else if(!strncmp(cmd, CMD_RSA_SIGN_SIG_ALG, cmd_len))
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

            free(cmd);
            free(data);
        }
        else {
            // puts("empty\n");
        }
    }
}
