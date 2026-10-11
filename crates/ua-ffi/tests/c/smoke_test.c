/*
 * A C caller of ua_cryptography: the header compiles, the library links, and the memory protocol holds.
 * Built and run by the release workflow against each desktop library:
 *
 *   cc -I crates/ua-ffi/include crates/ua-ffi/tests/c/smoke_test.c -L <lib dir> -lua_cryptography -o smoke_test
 */
#include <stdio.h>
#include <string.h>

#include "ua_cryptography.h"

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #condition); \
      return 1;                                                         \
    }                                                                   \
  } while (0)

static UaBytes lend(const void *data, size_t len) {
  UaBytes bytes = {(const uint8_t *)data, len};
  return bytes;
}

static const UaBytes ABSENT = {NULL, 0};

/* Whether the buffer holds `text`: a UaBuffer is not NUL-terminated. */
static bool contains(UaBuffer buffer, const char *text) {
  size_t length = strlen(text);
  for (size_t offset = 0; offset + length <= buffer.len; offset++) {
    if (memcmp(buffer.data + offset, text, length) == 0) {
      return true;
    }
  }
  return false;
}

int main(void) {
  const char *message_text = "message";
  UaBytes message = lend(message_text, strlen(message_text));
  UaBuffer error_message = {NULL, 0};

  /* Kupyna-256 of "message", one-shot and in parts. */
  UaBuffer whole = {NULL, 0};
  CHECK(ua_dstu7564_calculate_hash(message, 256, &whole, &error_message) == UA_STATUS_OK);
  CHECK(whole.len == 32);
  UaHashState *state = NULL;
  UaBuffer parts = {NULL, 0};
  CHECK(ua_dstu7564_begin_hash(256, &state, NULL) == UA_STATUS_OK);
  CHECK(ua_update_hash(state, lend(message_text, 3), NULL) == UA_STATUS_OK);
  CHECK(ua_update_hash(state, lend(message_text + 3, 4), NULL) == UA_STATUS_OK);
  CHECK(ua_end_hash(state, &parts, NULL) == UA_STATUS_OK);
  CHECK(parts.len == whole.len && memcmp(parts.data, whole.data, whole.len) == 0);
  ua_free_buffer(parts);
  ua_free_buffer(whole);

  /* A refusal carries its status and its message. */
  UaBuffer refused = {NULL, 0};
  CHECK(ua_dstu7564_calculate_hash(message, 128, &refused, &error_message) == UA_STATUS_INVALID_ARGUMENT);
  CHECK(error_message.len > 0);
  ua_free_buffer(error_message);

  /* DSTU 4145 on the 257-bit polynomial curve: a signature verifies, a tampered one does not. */
  UaCurve curve = {UA_CURVE_BASIS_POLYNOMIAL, 257};
  UaBuffer private_key = {NULL, 0};
  UaBuffer public_key = {NULL, 0};
  CHECK(ua_dstu4145_generate_key_pair(curve, &private_key, &public_key, NULL) == UA_STATUS_OK);
  UaBuffer signature = {NULL, 0};
  CHECK(ua_dstu4145_sign_message(curve, lend(private_key.data, private_key.len), message, ABSENT, 0, &signature,
                                 NULL) == UA_STATUS_OK);
  bool is_valid = false;
  CHECK(ua_dstu4145_verify_message(curve, lend(public_key.data, public_key.len), message, ABSENT,
                                   lend(signature.data, signature.len), &is_valid, NULL) == UA_STATUS_OK);
  CHECK(is_valid);
  signature.data[0] ^= 1;
  CHECK(ua_dstu4145_verify_message(curve, lend(public_key.data, public_key.len), message, ABSENT,
                                   lend(signature.data, signature.len), &is_valid, NULL) == UA_STATUS_OK);
  CHECK(!is_valid);
  ua_free_buffer(signature);
  ua_free_buffer(public_key);
  ua_free_buffer(private_key);

  /* Kalyna-GCM: a forged tag is an authentication failure. */
  uint8_t key[32] = {1};
  uint8_t nonce[16] = {2};
  UaBuffer sealed = {NULL, 0};
  CHECK(ua_dstu7624_gcm_encrypt(256, lend(key, 32), lend(nonce, 16), ABSENT, message, 128, &sealed, NULL) ==
        UA_STATUS_OK);
  sealed.data[0] ^= 1;
  UaBuffer opened = {NULL, 0};
  CHECK(ua_dstu7624_gcm_decrypt(256, lend(key, 32), lend(nonce, 16), ABSENT, lend(sealed.data, sealed.len), 128,
                                &opened, NULL) == UA_STATUS_AUTHENTICATION_FAILED);
  ua_free_buffer(sealed);

  /* A key store, a CAdES signature of a file, and its verification as JSON. */
  UaKeyStoreRequest request = {"CN=Smoke Test,C=UA", NULL, 257, 30, UA_SIGNATURE_HASH_DSTU7564};
  UaBuffer key_store = {NULL, 0};
  UaBuffer certificate = {NULL, 0};
  CHECK(ua_create_key_store(&request, "password", &key_store, &certificate, NULL) == UA_STATUS_OK);
  UaNamedBytes file = {"document.txt", message};
  UaSigningOptions options = {UA_SIGNATURE_FORMAT_CADES, UA_SIGNATURE_LEVEL_B, UA_SIGNATURE_HASH_DSTU7564, false,
                              false, NULL, NULL};
  UaBuffer cades = {NULL, 0};
  CHECK(ua_sign(lend(key_store.data, key_store.len), "password", NULL, &file, 1, NULL, 0, &options, &cades, NULL) ==
        UA_STATUS_OK);
  UaBytes trust = lend(certificate.data, certificate.len);
  UaBuffer report = {NULL, 0};
  CHECK(ua_verify(lend(cades.data, cades.len), NULL, 0, &trust, 1, NULL, 0, false, &report, NULL) == UA_STATUS_OK);
  CHECK(contains(report, "\"is_valid\":true"));
  ua_free_buffer(report);
  ua_free_buffer(cades);
  ua_free_buffer(certificate);
  ua_free_buffer(key_store);

  printf("ua_cryptography %s: the smoke test passed.\n", ua_get_version());
  return 0;
}
