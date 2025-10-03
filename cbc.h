#ifndef CBC_H
#define CBC_H
#include "speck.h"

void cbc_enc(const byte k[2*NBYTES],const byte *m, byte *c,size_t mlen);
void cbc_dec(const byte k[2 * NBYTES], byte *m, const byte *c, size_t mlen);
void xor_array(const byte* m0, const byte* m1, byte*c, const size_t n);

#endif 
