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

/*! \fn EVP_PKEY *load_dsa_public_key_der(unsigned char *data, unsigned long size)
 *  \brief Returns the dsa public key from stored in data in a DER format, the function return NULL if it can't get the public key
 *
 *  \param data Data buffer that hold public key DER Format
 *  \param size Size of the data buffer
  *  \return NULL, EVP_PKEY *.
 */
EVP_PKEY *load_dsa_public_key_der(unsigned char *data, unsigned long size);
/*! \fn EVP_PKEY *load_dsa_public_key_pem(unsigned char *data, unsigned long size)
 *  \brief Returns the dsa public key from stored in data in a PEM format, the function return NULL if it can't get the public key
 *
 *  \param data Data buffer that hold public key PEM Format
 *  \param size Size of the data buffer
  *  \return NULL, EVP_PKEY *.
 */
EVP_PKEY *load_dsa_public_key_pem(unsigned char *data, unsigned long size);
/*! \fn EVP_PKEY *load_public_key_x509(unsigned char *data, unsigned long size)
 *  \brief Returns the public key from stored in data in a X.509 format, the function return NULL if it can't get the public key
 *
 *  \param data Data buffer that hold public key X.509 Format
 *  \param size Size of the data buffer
  *  \return NULL, EVP_PKEY *.
 */
EVP_PKEY *load_public_key_x509(unsigned char *data, unsigned long size);
/*! \fn EVP_PKEY *load_dsa_public_key(unsigned char *data, unsigned long size)
 *  \brief Returns the public key from stored in data, it simply call all the three load functions, 
 *    the function return NULL if it can't get the public key
 *
 *  \param data Data buffer that hold public key X.509 Format
 *  \param size Size of the data buffer
  *  \return NULL, EVP_PKEY *.
 */
EVP_PKEY *load_dsa_public_key(unsigned char *data, int size);
/*! \fn EVP_PKEY *dsa_verify_signature(unsigned char *public_key_data, unsigned long public_key_data_size, unsigned char *signature_data, unsigned long signature_size, unsigned char *signed_data, unsigned long signed_data_size)
 *  \brief the function check the signature using DSA_Verify openssl function, it return 1 if the signature is valid, 0 otherwise
 *
 *  \param public_key_data Data buffer that hold public key
 *  \param public_key_data_size the Size of the data buffer holding the public key
 *  \param signature_data Data buffer that hold the signature
 *  \param signature_size the Size of the data buffer holding the signature
 *  \param signed_data Data buffer that hold the signed data
 *  \param signed_data_size the Size of the data buffer holding signed data
  *  \return return 1 if the signature is valid, 0 if not a valid signature or if an error occured.
 */
int dsa_verify_signature(
	unsigned char *public_key_data, unsigned long public_key_data_size, 
	unsigned char *signature_data, unsigned long signature_size, 
	unsigned char *signed_data, unsigned long signed_data_size);

/*! \fn EVP_PKEY *dsa_verify_signature(unsigned char *public_key_data, unsigned long public_key_data_size, unsigned char *signature_data, unsigned long signature_size, unsigned char *signed_data, unsigned long signed_data_size)
 *  \brief the function check the signature using EVP_DigestVerifyInit,EVP_DigestVerifyUpdate and EVP_DigestVerifyFinal openssl functions, it return 1 if the signature is valid, 0 otherwise
 *
 *  \param public_key_data Data buffer that hold public key
 *  \param public_key_data_size the Size of the data buffer holding the public key
 *  \param signature_data Data buffer that hold the signature
 *  \param signature_size the Size of the data buffer holding the signature
 *  \param signed_data Data buffer that hold the signed data
 *  \param signed_data_size the Size of the data buffer holding signed data
  *  \return return 1 if the signature is valid, 0 if not a valid signature or if an error occured.
 */
int dsa_verify_signature_2(
	unsigned char *public_key_data, unsigned long public_key_data_size,
	unsigned char *signature_data, unsigned long signature_size,
	unsigned char *signed_data, unsigned long signed_data_size)

#endif
