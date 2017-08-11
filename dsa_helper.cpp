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

EVP_PKEY *load_dsa_public_key_pem(unsigned char *data, unsigned long size) {
	BIO *pub_key = BIO_new_mem_buf(data, size);
	EVP_PKEY *public_key = NULL;
	
	if (pub_key == NULL) {
		return NULL;
	}

	DSA *dsa = PEM_read_bio_DSA_PUBKEY(pub_key, NULL, NULL, NULL);
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

EVP_PKEY *load_public_key_x509(unsigned char *data, unsigned long size) {
	X509 *x509 = NULL;
	BIO *cert = NULL;
	EVP_PKEY *pubKey = NULL;

	// Init
	x509 = X509_new();
	if (x509 == NULL) {
		return NULL;
	}

	// Getting Public Key From Certification
	cert = BIO_new_mem_buf(data, size);
	if (!cert) {
		X509_free(x509);
		return NULL;
	}

	x509 = d2i_X509_bio(cert, NULL);
	if (x509 == NULL) {
		BIO_free(cert);
		return NULL;
	}

	pubKey = X509_get_pubkey(x509);
	if (!pubKey) {
		X509_free(x509);
		BIO_free(cert);
		return NULL;
	}

	if (x509)
		X509_free(x509);
	if (cert)
		BIO_free(cert);

	return pubKey;
}
