#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "attack.h"

// print a block in hex
void print_block(const char *label, const byte *b) {
    printf("%s: ", label);
    for (int i = 0; i < NBYTES; i++)
        printf("%02x ", b[i]);
    printf("\n");
}

int main() {
    byte *m = NULL;
    byte *c = NULL;

    // Generate random message and its ciphertext
    size_t mlen = challenge(&m, &c);
    if (!m || !c || mlen == 0) {
        fprintf(stderr, "challenge() failed\n");
        return 1;
    }

    printf("challenge() generated %zu bytes (%zu blocks)\n", mlen, mlen / NBYTES);

    // Run the attack
    size_t collision[2];
    byte xor[NBYTES];

    attack(c, mlen + NBYTES, collision, xor);

    size_t i = collision[0];
    size_t j = collision[1];

    if (i == j) {
        printf("No collision found.\n");
    } else {
        printf("Collision between blocks %zu and %zu\n", i, j);

  
        print_block("C[i]", c + NBYTES + i * NBYTES);
        print_block("C[j]", c + NBYTES + j * NBYTES);

        // Recompute M[i] ⊕ M[j]
        byte actual_xor[NBYTES];
        for (int k = 0; k < NBYTES; ++k)
            actual_xor[k] = m[i * NBYTES + k] ^ m[j * NBYTES + k];

        print_block("Recovered M[i] ⊕ M[j]", xor);
        print_block("Actual    M[i] ⊕ M[j]", actual_xor);

        if (memcmp(xor, actual_xor, NBYTES) == 0) {
            printf("Attack suuccessful. XOR values match.\n");
        } else {
            printf(" XOR mismatch. Attack incorrect.\n");
        }
    }

    free(m);
    free(c);

    return 0;
}
