#include "dsa_helper.h"
/*
If an error occur check calling the 
OpenSSL_add_all_algorithms();
and load message so you can know what kind of error using ERR_load_crypto_strings();

To get the error you can use this piece of code 

char buffer[500];
ERR_error_string(ERR_get_error(), buffer);
std::cout << " ---- " << buffer << std::endl;

*/

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

EVP_PKEY *load_dsa_public_key(unsigned char *data, int size) {
	EVP_PKEY *pubKey = NULL;
	pubKey = load_dsa_public_key_der(data, size);
	
	if (pubKey) {
		return pubKey;
	}
	pubKey = load_dsa_public_key_pem(data, size);
	if (pubKey) {
		return pubKey;
	}
	pubKey = load_public_key_x509(data, size);
	
	return pubKey;
}

int dsa_verify_signature(
	unsigned char *public_key_data, unsigned long public_key_data_size, 
	unsigned char *signature_data, unsigned long signature_size, 
	unsigned char *signed_data, unsigned long signed_data_size)
{
	DSA *dsa = NULL;
	EVP_PKEY *public_key = load_dsa_public_key(public_key_data, public_key_data_size);

	if (!public_key) {
		return 0;
	}
	
	EVP_PKEY_set1_DSA(pubKey, dsa);

	if (dsa != NULL)
	{		
		int ret = DSA_verify(NID_sha1, signed_data, signed_data_size, signature_data, signature_size, dsa);
		if (ret != 1) {
			DSA_free(dsa);
			EVP_PKEY_free(pubKey);
			return 0;
		}
		else {
			return 1;
		}
	}

	return 0;
}

int dsa_verify_signature_2(
	unsigned char *public_key_data, unsigned long public_key_data_size,
	unsigned char *signature_data, unsigned long signature_size,
	unsigned char *signed_data, unsigned long signed_data_size)
{
	DSA* dsa = NULL;
	EVP_PKEY* pubKey = NULL;

	pubKey = load_dsa_public_key(public_key_data, public_key_data_size);
	if (!pubKey)
	{
		return 0;
	}

	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (!m_RSAVerifyCtx) {
		return 0;
	}

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha1(), NULL, pubKey) <= 0) {
		return 0;
	}

	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, signed_data, signed_data_size) <= 0) {
		return 0;
	}

	int ec = EVP_DigestVerifyFinal(m_RSAVerifyCtx, signature_data, signature_size);
	if (ec == 1) {
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
		return 1;
	}
	
	EVP_MD_CTX_destroy(m_RSAVerifyCtx);
	return 0;
}
