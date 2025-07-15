#include "ascon_hash.h"
#include "ascon.h"
#include "constants.h"
#include "permutations.h"
#include "word.h"

void ascon_hash(const uint8_t* input, size_t inlen, uint8_t* output) {
    ascon_state_t s;
    
    // Initialize state with ASCON-HASH IV
    s.x[0] = ASCON_HASH_IV;
    s.x[1] = 0;
    s.x[2] = 0;
    s.x[3] = 0;
    s.x[4] = 0;
    
    // Absorb all full blocks
    while (inlen >= ASCON_HASH_RATE) {
        s.x[0] ^= LOADBYTES(input, 8);
        P12(&s);
        input += ASCON_HASH_RATE;
        inlen -= ASCON_HASH_RATE;
    }
    
    // Absorb last block and padding
    uint64_t pad = PAD(inlen);
    s.x[0] ^= LOADBYTES(input, inlen) ^ pad;
    P12(&s);
    
    // Squeeze output
    STOREBYTES(output, s.x[0], 8);
    STOREBYTES(output + 8, s.x[1], 8);
    P12(&s);
    STOREBYTES(output + 16, s.x[0], 8);
    STOREBYTES(output + 20, s.x[1], 8);
}