#include "ethjet.h"
#include "tinykeccak.h"

#include <secp256k1_recovery.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// TODO Remove this lib
#include <stdio.h>

struct ethjet_context *
ethjet_init ()
{
  struct ethjet_context *ctx;
  ctx = malloc (sizeof *ctx);
  if (!ctx) return NULL;

  ctx->ec = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);

  return ctx;
}


void
ethjet_free (struct ethjet_context *ctx)
{
  secp256k1_context_destroy (ctx->ec);
  free (ctx);
}


/* 
 * The example contract at 0xdeadbeef just reverses its input.
 */
int
ethjet_example (struct ethjet_context *ctx,
                uint8_t *in, size_t in_size,
                uint8_t *out, size_t out_size)
{
  if (out_size != in_size)
    return 0;

  for (int i = 0; i < in_size; i++)
    out[i] = in[in_size - i - 1];

  return 1;
}


/*
 * Precompile 0x1 - ECDSA Recovery
 */
int
ethjet_ecrecover (secp256k1_context *ctx,
                  uint8_t *in, size_t in_size,
                  uint8_t *out, size_t out_size)
{
  /* Input: H V R S, all 32 bytes. */

  secp256k1_pubkey pubkey;
  secp256k1_ecdsa_recoverable_signature rsig;

  uint8_t *input64;
  uint8_t pubkey_hex[65];
  size_t hexlen = 65;

  int recid;

  if (in_size != 128)
    return 0;

  if (out_size != 32)
    return 0;

  input64 = in + 64;
  recid = in[63] - 27;

  if (recid < 0 || recid > 3)
    return 0;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact
      (ctx, &rsig, input64, recid))
    return 0;

  if (!secp256k1_ecdsa_recover (ctx, &pubkey, &rsig, in))
    return 0;

  if (!secp256k1_ec_pubkey_serialize
      (ctx, pubkey_hex, &hexlen, &pubkey, SECP256K1_EC_UNCOMPRESSED))
    return 0;

  if (sha3_256 (out, 32, pubkey_hex + 1, 64))
    return 0;

  memset (out, 0, 12);

  return 1;
}


/*
 * Precompile 0x2 - SHA2-256
 */
int
ethjet_sha256 (struct ethjet_context *ctx,
               uint8_t *in, size_t in_size,
               uint8_t *out, size_t out_size)
{
  return 0;
}


/*
 * Precompile 0x3 - RIPEMD-160
 */
int
ethjet_ripemd160 (struct ethjet_context *ctx,
                 uint8_t *in, size_t in_size,
                 uint8_t *out, size_t out_size)
{
  return 0;
}


/*
 * Precompile 0x4 - IDENTITY
 */
int
ethjet_identity (struct ethjet_context *ctx,
                 uint8_t *in, size_t in_size,
                 uint8_t *out, size_t out_size)
{
  if (out_size != in_size)
    return 0;

  for (int i = 0; i < in_size; i++)
    out[i] = in[i];

  return 1;
}


/*
 * FFI entry point. Execute a given precompiled contract.
 */
int
ethjet (struct ethjet_context *ctx,
        enum ethjet_operation op,
        uint8_t *in, size_t in_size,
        uint8_t *out, size_t out_size)
{
  switch (op) {
  case ETHJET_ECRECOVER:
    return ethjet_ecrecover (ctx->ec, in, in_size, out, out_size);
    break;

  case ETHJET_SHA256:
    ethjet_sha256 (ctx, in, in_size, out, out_size);
    break;

  case ETHJET_RIPEMD160:
    ethjet_ripemd160 (ctx, in, in_size, out, out_size);
    break;

  case ETHJET_IDENTITY:
    return ethjet_identity (ctx, in, in_size, out, out_size);
    break;

  case ETHJET_EXAMPLE:
    return ethjet_example (ctx, in, in_size, out, out_size);

  default:
    return 0;
  }
}
