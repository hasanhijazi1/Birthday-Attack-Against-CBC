#include <stdio.h>
#include <string.h>
#include "rand.h"
#include "speck.h"
#include "cbc.h"

// Function to print byte arrays
void print_bytes(const char *label, const byte *array, size_t length, const char *suffix) {
    printf("%s", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", array[i]);
    }
    printf("%s", suffix);
}

int main() {
    printf("Block size: 8*%d = %d; Key size: 16*%d = %d\n",
           NBYTES, NBYTES << 3, NBYTES, NBYTES << 4);

    byte k[2 * NBYTES];
    byte m[NBYTES];
    byte c[NBYTES];
    byte d[NBYTES];

    random_bytes(k, 2 * NBYTES);
    random_bytes(m, NBYTES);

    print_bytes("Key:              k = ", k, 2 * NBYTES, "\n");
    print_bytes("Message block:    m = ", m, NBYTES, "\n");

    cbc_enc(k, m, c, NBYTES);
    print_bytes("Ciphertext block: c = ", c, NBYTES, "\n");

    cbc_dec(k, d, c, NBYTES);
    print_bytes("Decrypted block:  d = ", d, NBYTES, "\n");

    return 0;
}
