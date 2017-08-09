#include <time.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/opensslconf.h>

#ifndef _DSA_HELPER_
#define _DSA_HELPER_

EVP_PKEY *load_dsa_public_key_der(unsigned char *data, unsigned long size);
EVP_PKEY *load_public_key_pem(unsigned char *data, unsigned long size);

#endif
