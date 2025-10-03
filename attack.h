#ifndef ATTACK_H
#define ATTACK_H
#include "cbc.h"
#include "speck.h"

size_t challenge(byte** m, byte** c);
void attack(const byte* c, size_t clen, size_t collision[2], byte xor[NBYTES]);
#define exponent (BLOCKSIZE/2+1)
#endif 