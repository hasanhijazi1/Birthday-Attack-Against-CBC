
# test_attack
gcc -o test_attack.run test_attack.c attack.c cbc.c speck.c rand.c -DBLOCKSIZE= '32 or 48 or 64'
# test_cbc
gcc -o test_cbc.run test_cbc.c cbc.c speck.c rand.c -DBLOCKSIZE='32 or 48 or 64'

# After building:
./test_cbc.run
./test_attack.run 


# Switching Between Brute Force and Optimized Attack
By default, the attack implementation in attack.c uses a hash-table based algorithm to reduce memory usage and support large inputs efficiently.

A brute-force O(n²) version is also implemented (but commented )
To try the brute-force attack:
    Comment the hash-based version
    Uncomment the nested-loop brute-force version:



