#include "dsa_helper.h"

EVP_PKEY *load_dsa_public_key_der(unsigned char *data, unsigned long size){
	BIO *pub_key = BIO_new_mem_buf(data, size);
	EVP_PKEY *public_key = NULL;
	
	if (pub_key == NULL) {
		return 0;
	}

	DSA * dsa = d2i_DSA_PUBKEY_bio(pub_key, NULL);

	if (dsa == NULL) {
		return NULL;
	}

	public_key = EVP_PKEY_new();
	
	if (!public_key) {
		BIO_free(pub_key);
		DSA_free(dsa);
		return NULL;
	}
	EVP_PKEY_set1_DSA(public_key, dsa);

	BIO_free(pub_key);
	DSA_free(dsa);

	return public_key;
}
