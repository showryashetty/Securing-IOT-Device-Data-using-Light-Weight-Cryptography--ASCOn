#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  *clen = mlen + CRYPTO_ABYTES;

  ascon_print("encrypt\n");
  ascon_printbytes("k", k, CRYPTO_KEYBYTES);
  ascon_printbytes("n", npub, CRYPTO_NPUBBYTES);
  ascon_printbytes("a", ad, adlen);
  ascon_printbytes("m", m, mlen);

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  ascon_printstate("init 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  ascon_printstate("init 2nd key xor", &s);

  if (adlen) {
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      ascon_printstate("absorb adata", &s);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    ascon_printstate("pad adata", &s);
    P8(&s);
  }

  s.x[4] ^= DSEP();
  ascon_printstate("domain separation", &s);

  while (mlen >= ASCON_128A_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], 8);
    ascon_printstate("absorb plaintext", &s);
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    mlen -= ASCON_128A_RATE;
  }
  if (mlen >= 8) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, mlen - 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], mlen - 8);
    s.x[1] ^= PAD(mlen - 8);
  } else {
    s.x[0] ^= LOADBYTES(m, mlen);
    STOREBYTES(c, s.x[0], mlen);
    s.x[0] ^= PAD(mlen);
  }
  m += mlen;
  c += mlen;
  ascon_printstate("pad plaintext", &s);

  s.x[2] ^= K0;
  s.x[3] ^= K1;
  ascon_printstate("final 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  ascon_printstate("final 2nd key xor", &s);

  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  ascon_printbytes("c", c - *clen + CRYPTO_ABYTES, *clen - CRYPTO_ABYTES);
  ascon_printbytes("t", c, CRYPTO_ABYTES);
  ascon_print("\n");

  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  *mlen = clen - CRYPTO_ABYTES;

  ascon_print("decrypt\n");
  ascon_printbytes("k", k, CRYPTO_KEYBYTES);
  ascon_printbytes("n", npub, CRYPTO_NPUBBYTES);
  ascon_printbytes("a", ad, adlen);
  ascon_printbytes("c", c, *mlen);
  ascon_printbytes("t", c + *mlen, CRYPTO_ABYTES);

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  ascon_printstate("init 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  ascon_printstate("init 2nd key xor", &s);

  if (adlen) {
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      ascon_printstate("absorb adata", &s);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    ascon_printstate("pad adata", &s);
    P8(&s);
  }

  s.x[4] ^= DSEP();
  ascon_printstate("domain separation", &s);

  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128A_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, 8);
    s.x[0] = c0;
    s.x[1] = c1;
    ascon_printstate("insert ciphertext", &s);
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    clen -= ASCON_128A_RATE;
  }

  if (clen >= 8) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, clen - 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, clen - 8);
    s.x[0] = c0;
    s.x[1] = CLEARBYTES(s.x[1], clen - 8);
    s.x[1] |= c1;
    s.x[1] ^= PAD(clen - 8);
  } else {
    uint64_t c0 = LOADBYTES(c, clen);
    STOREBYTES(m, s.x[0] ^ c0, clen);
    s.x[0] = CLEARBYTES(s.x[0], clen);
    s.x[0] |= c0;
    s.x[0] ^= PAD(clen);
  }
  m += clen;
  c += clen;
  ascon_printstate("pad ciphertext", &s);

  s.x[2] ^= K0;
  s.x[3] ^= K1;
  ascon_printstate("final 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  ascon_printstate("final 2nd key xor", &s);

  uint8_t t[16];
  STOREBYTES(t, s.x[3], 8);
  STOREBYTES(t + 8, s.x[4], 8);

  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  ascon_printbytes("m", m - *mlen, *mlen);
  ascon_print("\n");

  return result;
}
