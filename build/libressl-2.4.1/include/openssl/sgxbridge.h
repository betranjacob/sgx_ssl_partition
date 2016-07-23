#ifndef _SGXBRIDGE_H_
#define _SGXBRIDGE_H_

#define CMD_MAX_BUF_SIZE 1024
	
#define CMD_SESS_ID    "sess_id"
#define CMD_CLNT_RAND  "clnt_rand"
#define CMD_SRV_RAND   "srv_rand"
#define CMD_PREMASTER  "premaster"
#define CMD_MASTER_SEC "master_sec"
#define CMD_ALGO       "algo"
#define CMD_RSA_SIGN   "rsa_sign"
#define CMD_RSA_SIGN_SIG_ALG "rsa_sign_algo"

#define NAME_BUF_SIZE 256

int sgxbridge_init();
int opensgx_pipe_init(int flag_dir);
int opensgx_pipe_open(char* unique_id, int is_write, int flag_dir);
void sgxbridge_pipe_read(int len, char* data);
void sgxbridge_pipe_write(char* data, int len);
void sgxbridge_pipe_write_cmd(char* cmd, int len, char* data);
void print_hex(unsigned char* buf, int len);
void sgxbridge_generate_server_random(void* buf, int nbytes);
int sgxbridge_get_master_secret(unsigned char* buf);
void sgxbridge_rsa_sign_md(unsigned char* ip_md, int md_size,
                           unsigned char* op_sig, int* sig_size);
int sgxbridge_fetch_operation(int* cmd_len, char* cmd, int* data_len,
                              char* data);

#endif /* _SGXBRIDGE_H_ */