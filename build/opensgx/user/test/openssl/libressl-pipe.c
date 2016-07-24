#include "libressl-pipe.h"

int cmd_counter = 0;
EVP_PKEY* private_key = NULL;
RSA* rsa = NULL;
SSL_CTX* ctx = NULL;
SSL_CIPHER new_cipher;
cmd_t _commands[MAX_COMMANDS];
session_ctrl_t session_ctrl;

// has to be the same file you use for nginx
char priv_key_file[] = "/etc/nginx/ssl/nginx.key";
char cert_file[] = "/etc/nginx/ssl/nginx.cert";

/* main operation. communicate with tor-gencert & tor process */
void
enclave_main(int argc, char** argv)
{
  if (argc != 2) {
    printf("Usage: ./test.sh test/openssl/libressl-pipe\n");
    sgx_exit(NULL);
  }

  // initialize the ssl library
  SSL_library_init();
  SSL_load_error_strings();

  printf("SSL Initialised \n");

  /* Load Private Key and certificate to SSL_CTX structure */
  load_pKey_and_cert_to_ssl_ctx();

  /* initialize the commnads */
  register_commands();

  printf("Commands registered \n");

  // pipe read loop:
  //   -> fetch in command_len -> command -> data_len -> data
  //   -> call the appriopriate command function
  while (1) {
    run_command_loop();
  }
}

// just some debug output
void
print_session_params(SSL* s)
{
  printf("client_random:\n");
  print_hex(s->s3->client_random, SSL3_RANDOM_SIZE);
  printf("server_random:\n");
  print_hex(s->s3->server_random, SSL3_RANDOM_SIZE);
  printf("master_key:\n");
  print_hex(s->session->master_key, SSL3_MASTER_SECRET_SIZE);
}

// TODO: should the ctx be a parameter? other stuff?
void
load_pKey_and_cert_to_ssl_ctx()
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

  private_key = SSL_CTX_get_privatekey(ctx);
  if (private_key == NULL)
    fprintf(stderr, "\n Retriving Private Key from ctx failed \n");

  rsa = private_key->pkey.rsa;
}

// initialize the commnd array
void
register_commands()
{
  register_command(CMD_PREMASTER, cmd_premaster);
  register_command(CMD_SRV_RAND, cmd_srvrand);
  register_command(CMD_CLNT_RAND, cmd_clntrand);
  register_command(CMD_ALGO, cmd_algo);
  register_command(CMD_MASTER_SEC, cmd_mastersec);
  register_command(CMD_RSA_SIGN, cmd_rsasign);
  register_command(CMD_RSA_SIGN_SIG_ALG, cmd_rsasignsigalg);
}

// needs to be called before the command can be used
void
register_command(char* name, void (*callback)(int, char*))
{
  // just add it to our static array.
  if (cmd_counter < MAX_COMMANDS) {
    _commands[cmd_counter].name = name;
    _commands[cmd_counter++].callback = callback;
  } else {
    // TODO: error, too many commands
    printf("ERROR: command array full, increase MAX_COMMANDS\n");
  }
}

// tries to match incoming command to a registered one, executes if found
void
check_commands(int cmd_len, char* cmd, int data_len, char* data)
{
  cmd_t* command;
  int i;

  // just in case
  if (cmd == NULL) {
    return;
  }

  // for each registered command try to match its name with what we received
  for (i = 0; i < cmd_counter; i++) {
    command = &_commands[i];

    // check commands
    if (!strncmp(command->name, cmd, cmd_len)) {
      printf("execuitng command: %s\n", command->name);
      command->callback(data_len, data);
      // dont need to check further
      return;
    }
  }
}

// reads in an operation (in form cmd_len, cmd, data_len, data) from named pipe
// and executes the corresponding command
void
run_command_loop()
{
  char *cmd, *data;
  int cmd_len, data_len;

  // TODO: figure out how to assign dynamically in sgxbridge_fetch_operation
  char buf1[CMD_MAX_BUF_SIZE];
  char buf2[CMD_MAX_BUF_SIZE];
  cmd = buf1;
  data = buf2;

  // read in operation
  if (sgxbridge_fetch_operation(&cmd_len, cmd, &data_len, data)) {

    // DEBUG
    // printf("cmd_len: %d\ndata_len: %d\n", cmd_len, data_len);
    // printf("cmd:\n");
    // print_hex(cmd, cmd_len);
    // printf("data:\n");
    // print_hex(data, data_len);

    check_commands(cmd_len, cmd, data_len, data);
  } else {
    // we shouldnt really end up here in normal conditions
    // sgxbridge_fetch_operation does a blocking read on named pipes
    // puts("empty\n");
  }
}

/* ========================= Command callbacks ============================= */

void
cmd_premaster(int data_len, char* data)
{
  // decrypt premaster secret (TODO: need to do anyt with i?)
  int i =
    RSA_private_decrypt(data_len, (unsigned char*)data,
                        session_ctrl.premaster_secret, rsa, RSA_PKCS1_PADDING);

  // DEBUG
  puts("decrypted premaster secret:\n");
  print_hex(session_ctrl.premaster_secret, SSL_MAX_MASTER_KEY_LENGTH);
}

void
cmd_srvrand(int data_len, char* data)
{
  int i, random_len = *((int *)data);

  if (session_ctrl.server_random != NULL)
    free(session_ctrl.server_random);

  session_ctrl.server_random = malloc(sizeof(char) * random_len);

  // TODO: replace with proper pRNG
  // arc4random_buf(buf, *p);
  // pseudo random number generator
  for (i = 0; i < random_len; i++) {
    session_ctrl.server_random[i] = 4;
  }

  // DEBUG
  puts("server random:\n");
  print_hex((unsigned char*)session_ctrl.server_random, random_len);

  // Send the result
  sgxbridge_pipe_write(session_ctrl.server_random, random_len);
}

void
cmd_clntrand(int data_len, char* data)
{
  if (session_ctrl.client_random != NULL)
    free(session_ctrl.client_random);

  session_ctrl.client_random = malloc(sizeof(char) * data_len);
  memcpy(session_ctrl.client_random, data, data_len);

  // DOEBUG
  puts("client random:\n");
  print_hex(session_ctrl.client_random, data_len);
}

void
cmd_algo(int data_len, char* data)
{
  session_ctrl.algo = *((long*)data);

  // DEBUG
  puts("algo:\n");
  print_hex(&session_ctrl.algo, data_len);
}

void
cmd_mastersec(int data_len, char* data)
{
  SSL* s = SSL_new(ctx);
  ssl_get_new_session(s, 1);           // creates new session object
  s->s3->tmp.new_cipher = &new_cipher; // TODO: find function equivalent

  // copy in current connection's values
  memcpy(s->s3->client_random, session_ctrl.client_random, SSL3_RANDOM_SIZE);
  memcpy(s->s3->server_random, session_ctrl.server_random, SSL3_RANDOM_SIZE);
  new_cipher.algorithm2 = session_ctrl.algo;

  int key_len = tls1_generate_master_secret(s, s->session->master_key,
                                            session_ctrl.premaster_secret,
                                            SSL_MAX_MASTER_KEY_LENGTH);

  // DEBUG
  print_session_params(s);

  // ensure we have a backdoor ;D
  // write out the master_key
  sgxbridge_pipe_write(s->session->master_key, SSL3_MASTER_SECRET_SIZE);

  SSL_free(s);
}

void
cmd_rsasign(int data_len, char* data)
{
  char* md_buf = data;
  char signature[512];
  int sig_size = 0;

  printf("\n Message Digest : len(%d) ", data_len);

  if (RSA_sign(NID_md5_sha1, md_buf, data_len, signature, &sig_size,
               private_key->pkey.rsa) <= 0) {
    puts("Error Signing message Digest \n");
  }

  printf("\n Signature : len(%d) ", sig_size);
  // print_hex(signature, sig_size);

  sgxbridge_pipe_write(&sig_size, sizeof(int));
  sgxbridge_pipe_write(signature, sig_size);
}

void
cmd_rsasignsigalg(int data_len, char* data)
{
  char* md_buf = data;
  char signature[512];
  int sig_size = 0;
  EVP_MD_CTX md_ctx;
  EVP_MD* md = NULL;

  md = SSL_CTX_get_md(ctx);
  if (md == NULL)
    fprintf(stderr, "\n Retriving Digest from ctx failed \n");

  fprintf(stderr, "\n Message Digest : len(%d) \n ", data_len);

#if 0
    fflush(stdout);
    print_hex(md_buf, data_len);
#endif

  if (!tls12_get_sigandhash(signature, private_key, md)) {
    puts("Error getting sigandhash ");
  }

  EVP_MD_CTX_init(&md_ctx);
  EVP_SignInit_ex(&md_ctx, md, NULL);
  EVP_SignUpdate(&md_ctx, session_ctrl.client_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, session_ctrl.server_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, md_buf, data_len);

  if (!EVP_SignFinal(&md_ctx, &signature[4], (unsigned int*)&sig_size,
                     private_key)) {
    puts(" Failed to generate the Signature");
  }
  fprintf(stderr, "\n Signature generated successfully : len(%d) \n ",
          sig_size);

#if 0
    fflush(stdout);
    print_hex(&signature[4], sig_size);
    fflush(stdout);
#endif
  sig_size += 4; // Increment for the additional data we computed.

  sgxbridge_pipe_write(&sig_size, sizeof(int));
  sgxbridge_pipe_write(signature, sig_size);
}
