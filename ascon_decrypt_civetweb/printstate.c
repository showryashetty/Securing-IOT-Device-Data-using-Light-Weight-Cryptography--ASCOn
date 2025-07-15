#ifdef ASCON_PRINT_STATE

#include "printstate.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifndef WORDTOU64
#define WORDTOU64
#endif

#ifndef U64LE
#define U64LE
#endif

void ascon_print(const char* text) {
    printf("%s", text);
}

void ascon_printbytes(const char* text, const uint8_t* b, uint64_t len) {
    uint64_t i;
    printf(" %s[%" PRIu64 "]\t= {", text, len);
    for (i = 0; i < len; ++i)
        printf("0x%02x%s", b[i], i < len - 1 ? ", " : "");
    printf("}\n");
}

void ascon_printword(const char* text, const uint64_t x) {
    printf("%s=0x%016" PRIx64, text, U64LE(WORDTOU64(x)));
}

void ascon_printstate(const char* text, const ascon_state_t* s) {
    int i;
    printf("%s:", text);
    for (i = strlen(text); i < 17; ++i)
        printf(" ");
    ascon_printword(" x0", s->x[0]);
    ascon_printword(" x1", s->x[1]);
    ascon_printword(" x2", s->x[2]);
    ascon_printword(" x3", s->x[3]);
    ascon_printword(" x4", s->x[4]);
    printf("\n");
}

#endif
