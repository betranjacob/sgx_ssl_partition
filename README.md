# Intro to ssl-partition
This is a project for Networked Computer Systems MSc at UCL.

As hosting a webserver in the cloud is becoming more widespread, there are rising concerns about the
security of your private key hanging out unencrypted in the hands of the cloud service provider 
through the underlying OS or hypervisor.

We want to be prepared for when the Intel SGX hardware hits the clouds. Until that happens
OpenSGX does a pretty good job at emulating the hardware at instruction level and providing
a familiar development environment.

ssl-partition splits the ssl code so that the sensitive operations needing access to key material
are enclosed within an SGX enclave.

The feasibility of the idea was tested using nginx with statically linked libressl as the webserver
and opensgx with libressl as an enclave program.

# How do I run it?

clone the repo and run:

```bash
./build-ssl-partition.sh -g
```

this will compile opensgx, and nginx with libressl
now go to

```bash
cd build/opensgx/user
```

copy the nginx private key somewhere where unprivilidged user can access and change the path in libressl-pipe.c
```bash
cp -r /etc/nginx/ssl/ ./test/keys 
```
```c
// TODO: change location to point to YOUR files
char priv_key_file[] = "/home/USER_NAME/Documents/tmp/ssl-partition/build/opensgx/user/test/keys/nginx.key";
char cert_file[] = "/home/USER_NAME/Documents/tmp/ssl-partition/build/opensgx/user/test/keys/nginx.crt";
```

run the opensgx side of the pipe
```bash
./test.sh test/openssl/libressl-pipe
```

in a different window/tab run nginx
```bash
sudo nginx
```

go to your browser and connect to 
https://localhost


# Testing DHE using openssl client 

Run ssl client in a terminal 

```bash
openssl s_client -tls1 -cipher ECDHE -connect 127.0.0.1:443
```

