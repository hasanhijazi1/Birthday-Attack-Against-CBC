
#include "rand.h"
#include "speck.h"
#include "cbc.h"
#include <string.h>  

void cbc_enc(const byte k[2 * NBYTES],const byte *m, byte *c, size_t mlen) {
    byte iv[NBYTES];
    random_bytes(iv, NBYTES); 
    memcpy(c, iv, NBYTES); 

    int num_blocks = mlen / NBYTES;
    const byte *prev = iv;

    for (int i = 0; i < num_blocks; i++) {
        byte input[NBYTES];
        for (int j = 0; j < NBYTES; j++) {
            input[j] = m[i * NBYTES + j] ^ prev[j];
        }

        byte output[NBYTES];

        speck_enc(k, input, output);
        memcpy(c + NBYTES * (i + 1), output, NBYTES);

        prev = output;
    }
}

void cbc_dec(const byte k[2 * NBYTES], byte *m, const byte *c, size_t mlen) {
    const byte *iv = c;
    const byte *prev = iv;
    const byte *cipher_blocks = c + NBYTES;

    int num_blocks = mlen / NBYTES;

    for (int i = 0; i < num_blocks; i++) {
        byte decrypted[NBYTES];
        speck_dec(k, decrypted, cipher_blocks + i * NBYTES);

        for (int j = 0; j < NBYTES; j++) {
            m[i * NBYTES + j] = decrypted[j] ^ prev[j];
        }

        prev = cipher_blocks + i * NBYTES; 
    }
}
