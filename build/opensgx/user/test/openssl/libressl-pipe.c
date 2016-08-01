#include "libressl-pipe.h"

int cmd_counter = 0;
EVP_PKEY* private_key = NULL;
RSA* rsa = NULL;
SSL_CTX* ctx = NULL;
SSL_CIPHER new_cipher;
cmd_t _commands[MAX_COMMANDS];
session_ctrl_t session_ctrl;
SSL* s;
EC_KEY *ecdh;


// TODO: make it uniform with the script (crt / cert)
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

  printf("Initializing session ctrl...\n");
  init_session();
  printf("Session ctrl initialized\n");

  // pipe read loop:
  //   -> fetch in command_len -> command -> data_len -> data
  //   -> call the appriopriate command function
  while (1) {
    run_command_loop();
  }
}

void
init_session()
{
  if((session_ctrl.server_random = calloc(SSL3_RANDOM_SIZE, 1)) == NULL){
    fprintf(stderr, "server random calloc() failed: %s\n", strerror(errno));
    sgx_exit(NULL);
  }

  if((session_ctrl.client_random = calloc(SSL3_RANDOM_SIZE, 1)) == NULL){
    fprintf(stderr, "client random calloc() failed: %s\n", strerror(errno));
    sgx_exit(NULL);
  }
}

// just some debug output
void
print_session_params(SSL* s)
{
  printf("client_random:\n");
  print_hex(session_ctrl.client_random, SSL3_RANDOM_SIZE);
  printf("server_random:\n");
  print_hex(session_ctrl.server_random, SSL3_RANDOM_SIZE);
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
  register_command(CMD_SESS_ID, cmd_sess_id);
  register_command(CMD_CLNT_RAND, cmd_clnt_rand);
  register_command(CMD_SRV_RAND, cmd_srv_rand);
  register_command(CMD_PREMASTER, cmd_premaster);
  register_command(CMD_MASTER_SEC, cmd_master_sec);
  register_command(CMD_RSA_SIGN, cmd_rsa_sign);
  register_command(CMD_RSA_SIGN_SIG_ALG, cmd_rsa_sign_sig_alg);
  register_command(CMD_KEY_BLOCK, cmd_key_block);
  register_command(CMD_FINAL_FINISH_MAC, cmd_final_finish_mac);
  register_command(CMD_GET_ECDHE_PUBLIC_PARAM, cmd_ecdhe_get_public_param);
  register_command(CMD_GET_ECDHE_PRE_MASTER, cmd_ecdhe_generate_pre_master_key);
}

// needs to be called before the command can be used
void
register_command(int cmd, void (*callback)(int, char*))
{
  // just add it to our static array.
  if (cmd < MAX_COMMANDS) {
    _commands[cmd].cmd_num = cmd;
    _commands[cmd].callback = callback;
  } else {
    // TODO: error, too many commands
    printf("ERROR: command array full, increase MAX_COMMANDS\n");
  }
}

// tries to match incoming command to a registered one, executes if found
void
check_commands(int cmd, int data_len, char* data)
{
  if(cmd == _commands[cmd].cmd_num){
    printf("Execuitng command: %d\n", cmd);
    _commands[cmd].callback(data_len, data);
  } 
}

// reads in an operation (in form cmd_len, cmd, data_len, data) from named pipe
// and executes the corresponding command
void
run_command_loop()
{
  int cmd, data_len;
  char data[CMD_MAX_BUF_SIZE];

  // read in operation
  if (sgxbridge_fetch_operation(&cmd, &data_len, data)) {

    // DEBUG
    // printf("cmd_len: %d\ndata_len: %d\n", cmd_len, data_len);
    // printf("cmd:\n");
    // print_hex(cmd, cmd_len);
    // printf("data:\n");
    // print_hex(data, data_len);

    check_commands(cmd, data_len, data);
  } else {
    // we shouldnt really end up here in normal conditions
    // sgxbridge_fetch_operation does a blocking read on named pipes
    puts("empty\n");
  }
}

/* ========================= Command callbacks ============================= */

void
cmd_sess_id(int data_len, char* data)
{
  // TODO: store the old object somewhere here?

  s = SSL_new(ctx);
  ssl_get_new_session(s, 1);           // creates new session object
  s->s3->tmp.new_cipher = &new_cipher; // TODO: find function equivalent
  // set the session id

  if(data_len > 0) {
    memcpy(s->session->session_id, data, data_len);
    s->session->session_id_length = data_len;
  
    // DOEBUG
    puts("session_id:\n");
    print_hex(s->session->session_id, data_len);
  }
  else {
    // TODO: generate session id ourselves?
  }
}

void
cmd_clnt_rand(int data_len, char* data)
{
  // TODO: check on data_len?
  memcpy(session_ctrl.client_random, data, SSL3_RANDOM_SIZE);

  // DOEBUG
  puts("client random:\n");
  // print_hex(session_ctrl.client_random, data_len);
  print_hex(session_ctrl.client_random, data_len);
}

void
cmd_srv_rand(int data_len, char* data)
{
  int i, random_len = *((int *)data);

  // TODO: check on data len
  arc4random_buf(session_ctrl.server_random, SSL3_RANDOM_SIZE);

  // DEBUG
  puts("server random:\n");
  print_hex((unsigned char*) session_ctrl.server_random, random_len);

  // Send the result
  sgxbridge_pipe_write(session_ctrl.server_random, random_len);
}

void
cmd_premaster(int data_len, char* data)
{
  // decrypt premaster secret (TODO: need to do anyt with i?)
	session_ctrl.premaster_secret_length =
    RSA_private_decrypt(data_len, (unsigned char*)data,
                        session_ctrl.premaster_secret, rsa, RSA_PKCS1_PADDING);

  // DEBUG
  puts("decrypted premaster secret:\n");
  print_hex(session_ctrl.premaster_secret, session_ctrl.premaster_secret_length);
}

void
cmd_master_sec(int data_len, char* data)
{
  int ret;
  long *algo2 = (long *) data;
  unsigned char buf[SSL_MAX_MASTER_KEY_LENGTH];

  ret = tls1_PRF(*algo2,
      TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
      session_ctrl.client_random, SSL3_RANDOM_SIZE, NULL, 0,
      session_ctrl.server_random, SSL3_RANDOM_SIZE, NULL, 0,
      session_ctrl.premaster_secret, session_ctrl.premaster_secret_length,
      session_ctrl.master_key, buf, sizeof(buf));

  int i;
  fprintf(stdout, "master key:\n");
  for(i = 0; i < SSL_MAX_MASTER_KEY_LENGTH; i++){
    fprintf(stdout, "%x", session_ctrl.master_key[i]);
  }
  fprintf(stdout, "\n");

  if(s != NULL){
	  SSL_free(s);
	  s = NULL;
  }
}
void
cmd_rsa_sign(int data_len, char* data)
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
cmd_rsa_sign_sig_alg(int data_len, char* data)
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

void
cmd_key_block(int data_len, char *data){

    int ret;
    sgxbridge_st *sgxb;
    unsigned char *km, *tmp;

    sgxb = (sgxbridge_st *) data;
    km = malloc(sgxb->key_block_len);
    tmp = malloc(sgxb->key_block_len);

    ret = tls1_PRF(sgxb->algo2,
        TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
        session_ctrl.server_random, SSL3_RANDOM_SIZE,
        session_ctrl.client_random, SSL3_RANDOM_SIZE,
        NULL, 0, NULL, 0,
        session_ctrl.master_key, SSL3_MASTER_SECRET_SIZE,
        km, tmp, sgxb->key_block_len);

    int i;
    fprintf(stdout, "keyblock:\n");
    for(i = 0; i < 136; i++)
        fprintf(stdout, "%x", km[i]);
    fprintf(stdout, "\n");

    // if something went wrong, return length of 1 to indicate an error
    sgxbridge_pipe_write((char *) km, ret ? sgxb->key_block_len : 1);

    free(km);
    free(tmp);
}

void
cmd_final_finish_mac(int data_len, char *data){

  int ret;
  sgxbridge_st *sgxb;
  unsigned char buf2[12];
  unsigned char peer_finish_md[2 * EVP_MAX_MD_SIZE];

  sgxb = (sgxbridge_st *) data;

  ret = tls1_PRF(sgxb->algo2,
      sgxb->str, sgxb->str_len,
      sgxb->buf, sgxb->key_block_len,
      NULL, 0, NULL, 0, NULL, 0,
      session_ctrl.master_key, SSL3_MASTER_SECRET_SIZE,
      peer_finish_md, buf2, sizeof(buf2));

  int i;
  fprintf(stdout, "final finish MAC:\n");
  for(i = 0; i < 2 * EVP_MAX_MD_SIZE; i++)
      fprintf(stdout, "%x", peer_finish_md[i]);
  fprintf(stdout, "\n");

  // if something went wrong, return length of 1 to indicate an error
  sgxbridge_pipe_write((char *) peer_finish_md, ret ? 2 * EVP_MAX_MD_SIZE : 1);
}

void cmd_ecdhe_get_public_param(int data_len, char* data)
{
	CERT *cert = ctx->cert;
	const EC_GROUP *group;
	BN_CTX *bn_ctx = NULL;
	int ecdhe_params_size = 0;
	ecdhe_params *ep = (ecdhe_params *) calloc(sizeof(ecdhe_params), 1);

	int *d = (int *) data;
	ecdh = EC_KEY_new_by_curve_name(*d);
	if (ecdh == NULL) {
		fprintf(stderr, " EC_KEY_new_by_curve_name() failed \n");
		return;
	}

	if ((EC_KEY_get0_public_key(ecdh) == NULL)
			|| (EC_KEY_get0_private_key(ecdh) == NULL)) {
		/*(s->options & SSL_OP_SINGLE_ECDH_USE)) { */
		if (!EC_KEY_generate_key(ecdh)) {
			fprintf(stderr, "EC_KEY_generate_key () failed \n");
			return;
		}
	}

	if ((((group = EC_KEY_get0_group(ecdh)) == NULL)
			|| (EC_KEY_get0_public_key(ecdh) == NULL)
			|| (EC_KEY_get0_private_key(ecdh)) == NULL)) {
		fprintf(stderr, "EC_KEY_get0_group() failed \n");
		return;
	}

	// For now, we only support ephemeral ECDH  keys over named (not generic) curves. For supported named curves, curve_id is non-zero.
	if ((ep->curve_id = tls1_ec_nid2curve_id(EC_GROUP_get_curve_name(group)))
			== 0) {
		fprintf(stderr, "Failed to retrieve the group curve ID : \n");
		return;
	}

	// Encode the public key.  First check the size of encoding and  allocate memory accordingly.
	ep->encoded_length = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecdh),
			POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (ep->encoded_length > ENCODED_POINT_LEN_MAX) {
		fprintf(stderr, " No enough memory to hold  ENCODED_POINT!!! %d \n",
				ep->encoded_length);
		return;
	}

	bn_ctx = BN_CTX_new();
	if ((bn_ctx == NULL)) {
		fprintf(stderr, " BN_CTX_new Failed  \n");
		return;
	}
	ep->encoded_length = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecdh),
			POINT_CONVERSION_UNCOMPRESSED, ep->encodedPoint, ep->encoded_length,
			bn_ctx);
	if (ep->encoded_length == 0) {
		fprintf(stderr, " EC_POINT_point2oct() Failed  \n");
		return;
	}

	fprintf(stderr, "Server EC public key created successfully size(%d) \n",
			ep->encoded_length);
	ep->rsa_public_key_size = EVP_PKEY_size(private_key);

	BN_CTX_free(bn_ctx);
	bn_ctx = NULL;

	ecdhe_params_size = sizeof(ecdhe_params);

	fprintf(stderr, "Private Key %d Data Size %d \n", ep->rsa_public_key_size,
			ecdhe_params_size);

	sgxbridge_pipe_write(&ecdhe_params_size, sizeof(int));
	sgxbridge_pipe_write(ep, ecdhe_params_size);
	free(ep);
}

void cmd_ecdhe_generate_pre_master_key(int data_len, char* data)
{
	EVP_PKEY *clnt_pub_pkey = NULL;
	EC_POINT *clnt_ecpoint = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	int ec_key_size;

	group = EC_KEY_get0_group(ecdh);
	if (group == NULL) {
		fprintf(stderr, "EC_KEY_get0_group() failed \n");
		return;
	}

	// Let's get client's public key
	if ((clnt_ecpoint = EC_POINT_new(group)) == NULL) {
		fprintf(stderr, "EC_POINT_new() failed \n");
		return;
	}

	// Get client's public key from encoded point in the ClientKeyExchange message.
	if ((bn_ctx = BN_CTX_new()) == NULL) {
		fprintf(stderr, "BN_CTX_new() failed \n");
		return;
	}

	if (EC_POINT_oct2point(group, clnt_ecpoint, data, data_len, bn_ctx) == 0) {
		fprintf(stderr, "EC_POINT_oct2point() failed \n");
		return;
	}

	ec_key_size = ECDH_size(ecdh);
	if (ec_key_size <= 0) {
		fprintf(stderr, "ECDH_size() failed \n");
		return;
	}

	session_ctrl.premaster_secret_length = ECDH_compute_key(data, ec_key_size, clnt_ecpoint, ecdh, NULL);
	if (session_ctrl.premaster_secret_length <= 0) {
		fprintf(stderr, "ECDH_compute_key() failed \n");
		return;
	}
	fprintf(stderr, " EC_DHE Pre-Master Key computed successfully size(%d) \n",
			session_ctrl.premaster_secret_length);

	memcpy(session_ctrl.premaster_secret, data, session_ctrl.premaster_secret_length);

	EC_POINT_free(clnt_ecpoint);
	BN_CTX_free(bn_ctx);
	EC_KEY_free(ecdh);

}
