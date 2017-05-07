/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */


#include <assert.h>
#include <string.h>

#include <openssl/lhash.h>
#include <openssl/stack.h>
#include <openssl/buffer.h>
#include "../bytestring.h"
#include "pool.h"
#include "poo.h"

static uint32_t
CRYPTO_BUFFER_hash(const CRYPTO_BUFFER *buf) {
	return 42;
}

static int
CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *a, const CRYPTO_BUFFER *b) {
	if (a->len != b->len) {
		return 1;
	}
	return memcmp(a->data, b->data, a->len);
}

CRYPTO_BUFFER_POOL*
CRYPTO_BUFFER_POOL_new(void)
{
	CRYPTO_BUFFER_POOL *pool = malloc(sizeof(CRYPTO_BUFFER_POOL));
	return pool;
}

void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool)
{
	free(pool);
}

CRYPTO_BUFFER *
CRYPTO_BUFFER_new(const uint8_t *data, size_t len, CRYPTO_BUFFER_POOL *pool)
{
  CRYPTO_BUFFER *const buf = malloc(sizeof(CRYPTO_BUFFER));
  if (buf == NULL) {
    return NULL;
  }
  memset(buf, 0, sizeof(CRYPTO_BUFFER));

  buf->data = malloc(len);
  if (len != 0 && buf->data == NULL) {
    free(buf);
    return NULL;
  }
  if (len)
	  memcpy(buf, data, len);
  buf->len = len;
  buf->references = 1;

  buf->pool = NULL;
  return buf;
}

CRYPTO_BUFFER* CRYPTO_BUFFER_new_from_CBS(CBS *cbs, CRYPTO_BUFFER_POOL *pool)
{
	return CRYPTO_BUFFER_new(CBS_data(cbs), CBS_len(cbs), pool);
}

void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf)
{
	if (buf != NULL) {
		free(buf->data);
		free(buf);
	}
}

int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf)
{
	return 1;
}

const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf)
{
	return buf->data;
}

size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf)
{
	return buf->len;
}

void
CRYPTO_BUFFER_init_CBS(const CRYPTO_BUFFER *buf, CBS *out)
{
	CBS_init(out, buf->data, buf->len);
}
