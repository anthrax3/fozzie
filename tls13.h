
/* TLS 1.3 key derivation. */

/*
 * tls13_init_key_schedule initializes the handshake hash and key
 * derivation state. The cipher suite and PRF hash must have been
 * selected at this point.  It returns one on success and zero on
 * error.
 */
int tls13_init_key_schedule(SSL_HANDSHAKE *hs);

/*
 * tls13_init_early_key_schedule initializes the handshake hash and
 * key derivation state from the resumption secret to derive the early
 * secrets. It returns one on success and zero on error.
 */
int tls13_init_early_key_schedule(SSL_HANDSHAKE *hs);

/*
 * tls13_advance_key_schedule incorporates |in| into the key schedule
 * with HKDF-Extract. It returns one on success and zero on error.
 */
int tls13_advance_key_schedule(SSL_HANDSHAKE *hs, const uint8_t *in,
                               size_t len);


/* evp_aead_direction_t denotes the direction of an AEAD operation. */
/* XXX XXX XXX sigh */
enum evp_aead_direction_t {
  evp_aead_open,
  evp_aead_seal,
};

/*
 * tls13_set_traffic_key sets the read or write traffic keys to
 * |traffic_secret|. It returns one on success and zero on error.
 */
int tls13_set_traffic_key(SSL *ssl, enum evp_aead_direction_t direction,
                          const uint8_t *traffic_secret,
                          size_t traffic_secret_len);

/*
 * tls13_derive_early_secrets derives the early traffic secret. It
 * returns one on success and zero on error.
 */
int tls13_derive_early_secrets(SSL_HANDSHAKE *hs);

/*
 * tls13_derive_handshake_secrets derives the handshake traffic
 * secret. It returns one on success and zero on error.
 */
int tls13_derive_handshake_secrets(SSL_HANDSHAKE *hs);


/*
 * tls13_rotate_traffic_key derives the next read or write traffic
 * secret. It returns one on success and zero on error.
 */
int tls13_rotate_traffic_key(SSL *ssl, enum evp_aead_direction_t direction);

/*
 * tls13_derive_application_secrets derives the initial application
 * data traffic and exporter secrets based on the handshake
 * transcripts and |master_secret|.  It returns one on success and
 * zero on error.
 */
int tls13_derive_application_secrets(SSL_HANDSHAKE *hs);

/* tls13_derive_resumption_secret derives the |resumption_secret|. */
int tls13_derive_resumption_secret(SSL_HANDSHAKE *hs);

/*
 * tls13_export_keying_material provides an exporter interface to use
 * the |exporter_secret|.
 */
int tls13_export_keying_material(SSL *ssl, uint8_t *out, size_t out_len,
                                 const char *label, size_t label_len,
                                 const uint8_t *context, size_t context_len,
                                 int use_context);

/*
 * tls13_finished_mac calculates the MAC of the handshake transcript
 * to verify the integrity of the Finished message, and stores the
 * result in |out| and length in |out_len|. |is_server| is 1 if this
 * is for the Server Finished and 0 for the Client Finished.
 */
int tls13_finished_mac(SSL_HANDSHAKE *hs, uint8_t *out,
                       size_t *out_len, int is_server);

/*
 * tls13_write_psk_binder calculates the PSK binder value and replaces
 * the last bytes of |msg| with the resulting value. It returns 1 on
 * success, and 0 on failure.
 */
int tls13_write_psk_binder(SSL_HANDSHAKE *hs, uint8_t *msg, size_t len);

/*
 * tls13_verify_psk_binder verifies that the handshake transcript,
 * truncated up to the binders has a valid signature using the value
 * of |session|'s resumption secret. It returns 1 on success, and 0 on
 * failure.
 */
int tls13_verify_psk_binder(SSL_HANDSHAKE *hs, SSL_SESSION *session,
                            CBS *binders);


static inline int
ssl_add_message_cbb(SSL *ssl, CBB *cbb)
{
  uint8_t *msg;
  size_t len;
  if (!ssl->method->internal->finish_message(ssl, cbb, &msg, &len) ||
      !ssl->method->internal->add_message(ssl, msg, len)) {
    return 0;
  }

  return 1;
}
/* XXX XXX XXX */
#define SSL_KEY_UPDATE_NOT_REQUESTED 0
#define SSL_KEY_UPDATE_REQUESTED 1
