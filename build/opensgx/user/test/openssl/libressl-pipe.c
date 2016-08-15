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
  print_hex(session_ctrl.master_key, SSL3_MASTER_SECRET_SIZE);
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
  register_command(CMD_ENCRYPT_RECORD, cmd_encrypt_record);
  register_command(CMD_DECRYPT_RECORD, cmd_decrypt_record);
}

// needs to be called before the command can be used
void
register_command(int cmd, void (*callback)(int, unsigned char*))
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
check_commands(int cmd, int data_len, unsigned char* data)
{
  if(cmd == _commands[cmd].cmd_num){
    printf("Executing command: %d\n", cmd);
    _commands[cmd].callback(data_len, data);
  } 
}

// reads in an operation (in form cmd_len, cmd, data_len, data) from named pipe
// and executes the corresponding command
void
run_command_loop()
{
  int cmd, data_len;
  unsigned char data[CMD_MAX_BUF_SIZE];

  // read in operation
  if (sgxbridge_fetch_operation(&cmd, &data_len, data)) {

    // DEBUG
    // printf("cmd_len: %d\ndata_len: %d\n", cmd_len, data_len);
    // printf("cmd:\n");
    // print_hex((unsigned char *) cmd, cmd_len);
    // printf("data:\n");
    // print_hex((unsigned char *) data, data_len);

    check_commands(cmd, data_len, data);
  } else {
    // we shouldnt really end up here in normal conditions
    // sgxbridge_fetch_operation does a blocking read on named pipes
    //puts("empty\n");
  }
}

/* ========================= Command callbacks ============================= */

void
cmd_sess_id(int data_len, unsigned char* data)
{
  // TODO: store the old object somewhere here?

  s = SSL_new(ctx);
  ssl_get_new_session(s, 1);           // creates new session object
  s->s3->tmp.new_cipher = &new_cipher; // TODO: find function equivalent
  // set the session id

  if(data_len > 0) {
    memcpy(s->session->session_id, data, data_len);
    s->session->session_id_length = data_len;
  
    // DEBUG
    puts("session_id:\n");
    print_hex(s->session->session_id, data_len);
  }
  else {
    // TODO: generate session id ourselves?
  }
}

void
cmd_clnt_rand(int data_len, unsigned char* data)
{
  // TODO: check on data_len?
  memcpy(session_ctrl.client_random, data, SSL3_RANDOM_SIZE);

  // DEBUG
  printf("client random:\n");
  print_hex(session_ctrl.client_random, data_len);
}

void
cmd_srv_rand(int data_len, unsigned char* data)
{
  int random_len = *((int *)data);

  // TODO: check on data len
  arc4random_buf(session_ctrl.server_random, SSL3_RANDOM_SIZE);

  // DEBUG
  printf("server random:\n");
  print_hex(session_ctrl.server_random, random_len);

  // Send the result
  sgxbridge_pipe_write(session_ctrl.server_random, random_len);
}

void
cmd_premaster(int data_len, unsigned char* data)
{
  // decrypt premaster secret (TODO: need to do anyt with i?)
  session_ctrl.premaster_secret_length =
    RSA_private_decrypt(data_len,
        data, session_ctrl.premaster_secret, rsa, RSA_PKCS1_PADDING);

  // DEBUG
  puts("decrypted premaster secret:\n");
  print_hex(session_ctrl.premaster_secret,
      session_ctrl.premaster_secret_length);
}

void
cmd_master_sec(int data_len, unsigned char* data)
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

#if 0
  if(s != NULL){
    SSL_free(s);
    s = NULL;
  }
#endif
}

void
cmd_rsa_sign(int data_len, unsigned char* data)
{
  unsigned char* md_buf = (unsigned char *) data;
  unsigned char signature[512];
  unsigned int sig_size = 0;

  printf("\n Message Digest : len(%d) ", data_len);

  if (RSA_sign(NID_md5_sha1, md_buf, data_len, signature, &sig_size,
               private_key->pkey.rsa) <= 0) {
    puts("Error Signing message Digest \n");
  }

  printf("\n Signature : len(%d) ", sig_size);
  // print_hex(signature, sig_size);

  sgxbridge_pipe_write((unsigned char *) &sig_size, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) signature, sig_size);
}

void
cmd_rsa_sign_sig_alg(int data_len, unsigned char* data)
{
  unsigned char* md_buf = data;
  char signature[512];
  int sig_size = 0;
  EVP_MD_CTX md_ctx;
  EVP_MD* md = NULL;

  md = SSL_CTX_get_md(ctx);
  if (md == NULL)
    fprintf(stderr, "\n Retriving Digest from ctx failed \n");

  fprintf(stdout, "\n Message Digest : len(%d) \n ", data_len);

#if 0
    fflush(stdout);
    print_hex(md_buf, data_len);
#endif

  if (!tls12_get_sigandhash((unsigned char *) signature, private_key, md)) {
    puts("Error getting sigandhash ");
  }

  EVP_MD_CTX_init(&md_ctx);
  EVP_SignInit_ex(&md_ctx, md, NULL);
  EVP_SignUpdate(&md_ctx, session_ctrl.client_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, session_ctrl.server_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, md_buf, data_len);

  if (!EVP_SignFinal(&md_ctx,
        (unsigned char *) &signature[4],
        (unsigned int*)&sig_size,
        private_key))
    puts(" Failed to generate the Signature");

  fprintf(stdout, "\n Signature generated successfully : len(%d)\n", sig_size);

#if 0
    fflush(stdout);
    print_hex(&signature[4], sig_size);
    fflush(stdout);
#endif

  sig_size += 4; // Increment for the additional data we computed.

  sgxbridge_pipe_write((unsigned char *) &sig_size, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) signature, sig_size);
}

void
setup_cipher_stuff(sgxbridge_st *sgxb)
{
  new_cipher = sgxb->s_cipher;

  s->s3->tmp.new_cipher = &new_cipher;
  s->session->cipher = &new_cipher;
  s->session->ssl_version = sgxb->ssl_version;
  s->s3->tmp.key_block_length = sgxb->key_block_len;

  printf("algo2: %d\n", s->s3->tmp.new_cipher->algorithm2);
  // do magic
  // ssl_cipher_get_evp_aead_from_cipher(s_cipher_p, &s->s3->tmp.new_aead);
  ssl_cipher_get_evp_aead(s->session, &s->s3->tmp.new_aead);
  // ssl_cipher_get_evp_from_cipher(s_cipher_p, &s->s3->tmp.new_sym_enc, &s->s3->tmp.new_hash, &s->s3->tmp.new_mac_pkey_type, &s->s3->tmp.new_mac_secret_size);
  // ssl_cipher_get_evp(s->session, &s->s3->tmp.new_sym_enc, &s->s3->tmp.new_hash, &s->s3->tmp.new_mac_pkey_type, &s->s3->tmp.new_mac_secret_size);
  int ret;
  ret = tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_READ);
  printf("read cipher change ret: %d\n", ret);
  ret = tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_WRITE);
  printf("write cipher change ret: %d\n", ret);
  // if (s_cipher_p->algorithm2 & SSL_CIPHER_ALGORITHM2_AEAD) {
  //   if (!ssl_cipher_get_evp_aead_from_cipher(s_cipher_p, &aead)) {
  //        fprintf(stdout, " ssl_cipher_get_evp_aead_from_cipher() failed \n");
  //      return ;
  //   }
   
  //   fprintf(stdout, " AEAD :: ssl_cipher_get_evp_aead_from_cipher() success \n");
 
  //    key_len = EVP_AEAD_key_length(aead);
  //    iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s_cipher_p);
  // } else {
  //   if (!ssl_cipher_get_evp_from_cipher(s_cipher_p, &cipher, &mac, &mac_type,
  //       &mac_secret_size)) {
  //       fprintf(stdout, " ssl_cipher_get_evp_from_cipher() failed \n");
  //       return ;
  //   }
  //   fprintf(stdout, " EVP :: ssl_cipher_get_evp_from_cipher() success \n");
 
  //   key_len = EVP_CIPHER_key_length(cipher);
  //   iv_len = EVP_CIPHER_iv_length(cipher);
 
  //    /* If GCM mode only part of IV comes from PRF. */
  //   if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
  //      iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
  //  }


  // printf("before SSL3_CHANGE_CIPHER_SERVER_READ\n");
  // tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_READ);
  // printf("after SSL3_CHANGE_CIPHER_SERVER_READ\n");
  // tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_WRITE);
  // printf("after SSL3_CHANGE_CIPHER_SERVER_WRITE\n");
  
}

void
cmd_key_block(int data_len, unsigned char* data){

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

  // printf("memcopying to s->s3->tmp.key_block\n");
  // memcpy(s->s3->tmp.key_block, km, sgxb->key_block_len);
  printf("tls1_PRF ret: %d\n", ret);
  printf("sgxb ciph algo2: %d\n", sgxb->s_cipher.algorithm2);

  s->s3->tmp.key_block = km;
  sgxb->s_cipher.algorithm2 = sgxb->algo2;
  // s->s3->tmp.key_block_length = 64;

  // s->s3->tmp.new_aead = aead;
  // s->s3->tmp.new_sym_enc = cipher;
  // s->s3->tmp.new_hash = mac;
  // s->s3->tmp.new_mac_pkey_type = mac_type;
  // s->s3->tmp.new_mac_secret_size = mac_secret_size;

  setup_cipher_stuff(sgxb);


	fprintf(stdout, "keyblock (%d)\n", 136);
  print_hex(km, 136);

	// if something went wrong, return length of 1 to indicate an error
	sgxbridge_pipe_write((unsigned char *) km, ret ? sgxb->key_block_len : 1);

	// free(km); // this will need to be accessed later
	free(tmp);
}

void
cmd_encrypt_record(int data_len, unsigned char* data)
{
	app_data_encrypt *rec = (app_data_encrypt *)data;
	const SSL_AEAD_CTX *aead;
	int i, out_length = 0;
	unsigned char out[256];

  aead = s->aead_write_ctx;

  // tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_WRITE);

#if 0
  fprintf(stdout, " Data from ngx : %d - %d \n", sizeof(app_data_encrypt), data_len);
	fprintf(stdout, " L- %d rec->nonce_used %d evlen %d, len %d\n", __LINE__, rec->nonce_used, rec->eiv_length, rec->record_length);

	fprintf(stdout, " Printing AD (%d)\n", sizeof(rec->ad));
	print_hex(rec->ad, sizeof(rec->ad));

	fprintf(stdout, " Printing INPUT before encrypt (%d)\n", rec->record_length);
	print_hex(rec->data_record, rec->record_length);

	memcpy(out, rec->out_data, 256);
	fprintf(stdout, " Printing OUTPUT before encrypt (%d)\n", rec->record_length+aead->tag_len);
	print_hex(out, rec->record_length + aead->tag_len);

	fprintf(stdout, " Printing nonce (16)\n");
	print_hex(rec->nonce, 16);
#endif

	memcpy(out, rec->out_data, 256);

	//if (!EVP_AEAD_CTX_seal(&aead->ctx, (&rec->out_data)+rec->eiv_length, &out_length, rec->record_length + aead->tag_len, rec->nonce,
	if (!EVP_AEAD_CTX_seal(&aead->ctx, out, &out_length, rec->record_length + aead->tag_len, rec->nonce,
	    rec->nonce_used, rec->data_record + rec->eiv_length, rec->record_length, rec->ad, sizeof(rec->ad)))
	{
		fprintf(stdout, "EVP_AEAD_CTX_seal () failed \n");
		return;
	}

  fprintf(stdout, " Printing OUTPUT after encrypt (%d)\n", out_length);
	print_hex(out, out_length);

	fprintf(stdout, "Writing data to server (%d)\n",out_length);

	sgxbridge_pipe_write((unsigned char *) &out_length, sizeof(int));
	sgxbridge_pipe_write((unsigned char *) out, out_length);
}

// TODO: merge into 1 command with encrypt
void
cmd_decrypt_record(int data_len, unsigned char* data)
{
  app_data *rec = (app_data *)data;
  const SSL_AEAD_CTX *aead;
  int i, out_len = 0;
  
  // tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_READ);
  aead = s->aead_read_ctx;

  // tls1_change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_READ);

  fprintf(stdout, " Data from ngx : %d - %d\n", sizeof(app_data), data_len);
  fprintf(stdout, " L- %d rec->nonce_used %d evlen %d, len%d\n", __LINE__, rec->nonce_used, rec->eivlen, rec->in_len);

  fprintf(stdout, " Printing AD:\n");
  print_hex(rec->ad, sizeof(rec->ad));

  fprintf(stdout, " Printing INPUT before decrypt (%d)\n", rec->in_len);
  print_hex(rec->in, rec->in_len);

  fprintf(stdout, " Printing nonce (16)\n");
  print_hex(rec->nonce, 16);


  if (!EVP_AEAD_CTX_open(&aead->ctx, rec->out, &out_len, rec->in_len,
          rec->nonce, rec->nonce_used, rec->in, rec->in_len + aead->tag_len, rec->ad,
          sizeof(rec->ad)))
  {
    fprintf(stdout, "EVP_AEAD_CTX_open () failed \n");
    return;
  }

  //memcpy()
  fprintf(stdout, " Printing INPUT after decrypt (%d) ", out_len);
  print_hex(rec->out, out_len);

  fprintf(stdout, "Writing data to server (%d) \n", out_len);

  sgxbridge_pipe_write((unsigned char *) &out_len, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) rec->out, out_len);
}

void
cmd_final_finish_mac(int data_len, unsigned char* data){

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
  sgxbridge_pipe_write(peer_finish_md, ret ? 2 * EVP_MAX_MD_SIZE : 1);
}

void cmd_ecdhe_get_public_param(int data_len, unsigned char* data)
{
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

  // For now, we only support ephemeral ECDH  keys over named (not generic)
  // curves. For supported named curves, curve_id is non-zero.
  if ((ep->curve_id = tls1_ec_nid2curve_id(EC_GROUP_get_curve_name(group)))
      == 0) {
    fprintf(stderr, "Failed to retrieve the group curve ID : \n");
    return;
  }

  // Encode the public key. First check the size of encoding and  allocate
  // memory accordingly.
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

  ep->encoded_length = EC_POINT_point2oct(group,
      EC_KEY_get0_public_key(ecdh),
      POINT_CONVERSION_UNCOMPRESSED,
      (unsigned char *) ep->encodedPoint,
      ep->encoded_length,
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

  sgxbridge_pipe_write((unsigned char *) &ecdhe_params_size, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) ep, ecdhe_params_size);
  free(ep);
}

void cmd_ecdhe_generate_pre_master_key(int data_len, unsigned char* data)
{
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

  // Get client's public key from encoded point in the ClientKeyExchange
  // message.
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

  session_ctrl.premaster_secret_length =
    ECDH_compute_key(data, ec_key_size, clnt_ecpoint, ecdh, NULL);

  if (session_ctrl.premaster_secret_length <= 0) {
    fprintf(stderr, "ECDH_compute_key() failed \n");
    return;
  }
  fprintf(stderr, " EC_DHE Pre-Master Key computed successfully size(%d) \n",
      session_ctrl.premaster_secret_length);

  memcpy(session_ctrl.premaster_secret,
      data, session_ctrl.premaster_secret_length);

  EC_POINT_free(clnt_ecpoint);
  BN_CTX_free(bn_ctx);
  EC_KEY_free(ecdh);
}
