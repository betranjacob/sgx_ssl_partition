#define SGX_SESSION_ID_LENGTH SSL_MAX_SSL_SESSION_ID_LENGTH

void enclave_main(int argc, char** argv);

int main(int argc, char** argv){
	enclave_main(argc, argv);
	return 0;
}

