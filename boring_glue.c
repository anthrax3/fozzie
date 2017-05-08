/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/ssl.h>

#include <limits.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../ssl_locl.h"
#include "../../libcrypto/asn1/asn1_locl.h"
#include "tls13.h"

#if 0 /* XXX unfuzzle cert versus SSL */
enum ssl_private_key_result_t
ssl_private_key_sign(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
    uint16_t sigalg, const uint8_t *in, size_t in_len)
{
	if (ssl->cert->key_method != NULL) {
		if (ssl->cert->key_method->sign != NULL) {
			return ssl->cert->key_method->sign(ssl, out, out_len,
			    max_out, sigalg, in, in_len);
		}

		/*
		 * TODO(davidben): Remove support for |sign_digest|-only
		 * |SSL_PRIVATE_KEY_METHOD|s.
		 */
		const SSL_SIGNATURE_ALGORITHM *alg = get_signature_algorithm(sigalg);
		if (alg == NULL ||
		    !legacy_sign_digest_supported(alg)) {
			SSLerrorx(SSL_R_UNSUPPORTED_PROTOCOL_FOR_CUSTOM_KEY);
			return ssl_private_key_failure;
		}

		const EVP_MD *md = alg->digest_func();
		uint8_t hash[EVP_MAX_MD_SIZE];
		unsigned hash_len;
		if (!EVP_Digest(in, in_len, hash, &hash_len, md, NULL)) {
			return ssl_private_key_failure;
		}

		return ssl->cert->key_method->sign_digest(ssl, out, out_len, max_out, md,
		    hash, hash_len);
	}

	*out_len = max_out;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ssl->cert->privatekey, NULL);
	int ret = ctx != NULL &&
	    EVP_PKEY_sign_init(ctx) &&
	    setup_ctx(ssl, ctx, sigalg) &&
	    EVP_PKEY_sign_message(ctx, out, out_len, in, in_len);
	EVP_PKEY_CTX_free(ctx);
	return ret ? ssl_private_key_success : ssl_private_key_failure;
}
#endif

int
ssl_public_key_verify(SSL *ssl, const uint8_t *signature,
    size_t signature_len, uint16_t signature_algorithm,
    EVP_PKEY *pkey, const uint8_t *in, size_t in_len)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	int ret = ctx != NULL &&
	    EVP_PKEY_verify_init(ctx) &&
	    setup_ctx(ssl, ctx, signature_algorithm) &&
	    EVP_PKEY_verify_message(ctx, signature, signature_len, in, in_len);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

#if 0
enum ssl_private_key_result_t
ssl_private_key_complete(SSL *ssl, uint8_t *out, size_t *out_len,
    size_t max_out)
{
	/* Only custom keys may be asynchronous. */
	return ssl->cert->key_method->complete(ssl, out, out_len, max_out);
}
#endif
/*
 * Ss_cert_skip_to_spki parses a DER-encoded, X.509 certificate from
 * |in| and positions |*out_tbs_cert| to cover the TBSCertificate,
 * starting at the subjectPublicKeyInfo.
 */
static int ssl_cert_skip_to_spki(const CBS *in, CBS *out_tbs_cert) {
  /*
   * From RFC 5280, section 4.1
   *    Certificate  ::=  SEQUENCE  {
   *      tbsCertificate       TBSCertificate,
   *      signatureAlgorithm   AlgorithmIdentifier,
   *      signatureValue       BIT STRING  }
   *
   * TBSCertificate  ::=  SEQUENCE  {
   *      version         [0]  EXPLICIT Version DEFAULT v1,
   *      serialNumber         CertificateSerialNumber,
   *      signature            AlgorithmIdentifier,
   *      issuer               Name,
   *      validity             Validity,
   *      subject              Name,
   *      subjectPublicKeyInfo SubjectPublicKeyInfo,
   *      ... }
   */
  CBS buf = *in;
  CBS toplevel;

  if (!CBS_get_asn1(&buf, &toplevel, CBS_ASN1_SEQUENCE) ||
      CBS_len(&buf) != 0 ||
      !CBS_get_asn1(&toplevel, out_tbs_cert, CBS_ASN1_SEQUENCE) ||
      /* version */
      !CBS_get_optional_asn1(
          out_tbs_cert, NULL, NULL,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0) ||
      /* serialNumber */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_INTEGER) ||
      /* signature algorithm */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* issuer */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* validity */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* subject */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE)) {
    return 0;
  }

  return 1;
}

static int parse_key_type(CBS *cbs, int *out_type)
{
	CBS oid;
	unsigned int i;

	if (!CBS_get_asn1(cbs, &oid, CBS_ASN1_OBJECT)) {
		return 0;
	}
#if 0 /* XXX XXX XXX work around EVP_PKEY_ASN1 goo */
	for (i = 0; i < OPENSSL_ARRAY_SIZE(kASN1Methods); i++) {
		const EVP_PKEY_ASN1_METHOD *method = kASN1Methods[i];
		if (CBS_len(&oid) == method->oid_len &&
		    memcmp(CBS_data(&oid), method->oid, method->oid_len) == 0) {
			*out_type = method->pkey_id;
			return 1;
		}
	}
#endif

  return 0;
}


static EVP_PKEY *
EVP_parse_public_key(CBS *cbs)
{
	/* Parse the SubjectPublicKeyInfo. */
	EVP_PKEY *ret;
	const unsigned char * data;

	data = CBS_data(cbs);
	return d2i_PUBKEY(NULL, &data, CBS_len(cbs));
}

EVP_PKEY *ssl_cert_parse_pubkey(const CBS *in) {
  CBS buf = *in, tbs_cert;
  if (!ssl_cert_skip_to_spki(&buf, &tbs_cert)) {
//    SSLerrorx(SSL_R_CANNOT_PARSE_LEAF_CERT);
    return NULL;
  }

  return EVP_parse_public_key(&tbs_cert);
}
