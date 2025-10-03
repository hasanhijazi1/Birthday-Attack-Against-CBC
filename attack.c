#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "attack.h"
#include "rand.h"

size_t challenge(byte **m, byte **c)
{
    size_t nblocks = (size_t)pow(2, exponent); // >2^16 for 32, >2^24 for 48, >2^32 for 64
    size_t mlen = nblocks * NBYTES;
    size_t clen = mlen + NBYTES;

    *m = malloc(mlen);
    *c = malloc(clen);

    if (!*m || !*c)
    {
        fprintf(stderr, "Memory allocation failed\n");
        free(*m);
        free(*c);
        *m = NULL;
        *c = NULL;
        return 0;
    }

    random_bytes(*m, mlen);

    byte key[2 * NBYTES];
    random_bytes(key, 2 * NBYTES);
    cbc_enc(key, *m, *c, mlen);

    return mlen;
}

// Brute force

// void attack(const byte *c, size_t clen, size_t collision[2], byte xor [NBYTES])
// {
//     size_t nblocks = (clen - NBYTES) / NBYTES;
//     const byte *blocks = c + NBYTES;

//     for (size_t i = 0; i < nblocks; i++)
//     {
//         for (size_t j = i + 1; j < nblocks; j++)
//         {
//             const byte *block_i = blocks + i * NBYTES;
//             const byte *block_j = blocks + j * NBYTES;

//             if (memcmp(block_i, block_j, NBYTES) == 0)
//             {

//                 collision[0] = i;
//                 collision[1] = j;

//                 if (i > 0 && j > 0)
//                 {
//                     const byte *prev_i = blocks + (i - 1) * NBYTES;
//                     const byte *prev_j = blocks + (j - 1) * NBYTES;

//                     for (int k = 0; k < NBYTES; k++)
//                         xor[k] = prev_i[k] ^ prev_j[k];
//                 }
//                 else
//                 {
//                     memset(xor, 0, NBYTES);
//                 }

//                 return;
//             }
//         }
//     }

//     collision[0] = collision[1] = 0;
//     memset(xor, 0, NBYTES);
// }

// unsing hash for better complexity

typedef struct
{
    byte block[NBYTES];
    size_t index;
    int used;
} BlockTable;

void attack(const byte *c, size_t clen, size_t collision[2], byte xor[NBYTES]) {
    size_t nblocks = (clen - NBYTES) / NBYTES;
    const byte *blocks = c + NBYTES;
    size_t table_size = 2 * nblocks;

    BlockTable *table = calloc(table_size, sizeof(BlockTable));
    if (!table) {
        fprintf(stderr, "[ERROR] Memory allocation failed (size: %zu entries)\n", table_size);
        collision[0] = collision[1] = 0;
        memset(xor, 0, NBYTES);
        return;
    }

    for (size_t i = 0; i < nblocks; ++i) {
        const byte *block = blocks + i * NBYTES;

        uint64_t val = 0;
        memcpy(&val, block, sizeof(uint64_t));

        size_t h = val % table_size;

        while (table[h].used) {
            int equal = 1;

            for (int j = 0; j < NBYTES; j++) {
                if (table[h].block[j] != block[j]) {
                    equal = 0;  // mismatch
                    break;
                }
            }

            if (equal) {
                // collision found
                collision[0] = table[h].index;
                collision[1] = i;

                if (i > 0 && table[h].index > 0) {
                    const byte *prev_i = blocks + (i - 1) * NBYTES;
                    const byte *prev_j = blocks + (table[h].index - 1) * NBYTES;

                    for (size_t k = 0; k < NBYTES; ++k)
                        xor[k] = prev_i[k] ^ prev_j[k];
                } else {
                    memset(xor, 0, NBYTES);
                }

                free(table);
                return;
            }

            h = (h + 1) % table_size;
        }

     
        for (int j = 0; j < NBYTES; j++) {
            table[h].block[j] = block[j];
        }
        table[h].index = i;
        table[h].used = 1;
    }

    // No collision found
    collision[0] = collision[1] = 0;
    memset(xor, 0, NBYTES);
    free(table);
}
