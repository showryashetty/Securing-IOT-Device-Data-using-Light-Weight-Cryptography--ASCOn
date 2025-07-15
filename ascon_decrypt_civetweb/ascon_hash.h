#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stdint.h>
#include <stddef.h>

#define ASCON_HASH_SIZE 32

void ascon_hash(const uint8_t* input, size_t inlen, uint8_t* output);

#endif