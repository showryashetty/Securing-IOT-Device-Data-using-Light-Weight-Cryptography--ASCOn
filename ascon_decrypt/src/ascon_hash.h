#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void ascon_hash(const uint8_t* input, size_t inlen, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif
