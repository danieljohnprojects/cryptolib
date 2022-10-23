#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <IO.h>
#include <shacal_2.h>

void test_SHACAL_2_encrypt() {
    block_t message = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

    #ifdef VERBOSE
    printf("Encrypting message:\n");
    print_words32(message, 8);
    #endif


    // Can use the test vectors of SHA1, just need to subtract of initial state first.
    block_t expected_cipher = {
        0xba7816bf - 0x6a09e667,
        0x8f01cfea - 0xbb67ae85,
        0x414140de - 0x3c6ef372,
        0x5dae2223 - 0xa54ff53a,
        0xb00361a3 - 0x510e527f,
        0x96177a9c - 0x9b05688c,
        0xb410ff61 - 0x1f83d9ab,
        0xf20015ad - 0x5be0cd19,
    };

    uint32_t key[] = {
        0x61626380, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000018,
    };

    #ifdef VERBOSE
    printf("Using key:\n");
    print_words32(key, WORDS_PER_KEY);
    printf("\n");
    #endif

    #ifdef VERBOSE
    printf("Expanding key schedule...\n");
    #endif
    shacal_2_key_t key_schedule;
    initialise_key(key, key_schedule);

    #ifdef VERBOSE
    printf("Encrypting message...\n");
    #endif
    encrypt(key_schedule, message);

    #ifdef VERBOSE
    printf("\nEncrypted message:\n");
    print_words32(message, WORDS_PER_BLOCK);
    printf("Expected encryption:\n");
    print_words32(expected_cipher, WORDS_PER_BLOCK);
    #endif
    for (int i = 0; i < WORDS_PER_BLOCK; i++) {
        assert(message[i] == expected_cipher[i]);
    }
}

void test_SHACAL_2_decrypt() {
    // Use SHA1 test vector minus the input initialisation.
    block_t message = {
        0xba7816bf - 0x6a09e667,
        0x8f01cfea - 0xbb67ae85,
        0x414140de - 0x3c6ef372,
        0x5dae2223 - 0xa54ff53a,
        0xb00361a3 - 0x510e527f,
        0x96177a9c - 0x9b05688c,
        0xb410ff61 - 0x1f83d9ab,
        0xf20015ad - 0x5be0cd19,
    };
    block_t expected_plain = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

    uint32_t key[] = {
        0x61626380, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000018,
    };
    #ifdef VERBOSE
    printf("Using key:\n");
    print_words32(key, WORDS_PER_KEY);
    printf("\n");
    #endif

    #ifdef VERBOSE
    printf("Expanding key schedule...\n");
    #endif
    shacal_2_key_t key_schedule;
    initialise_key(key, key_schedule);

    #ifdef VERBOSE
    printf("Decrypting message...\n");
    #endif
    decrypt(key_schedule, message);

    #ifdef VERBOSE
    printf("\nDecrypted message:\n");
    print_words32(message, WORDS_PER_BLOCK);
    printf("Expected decryption:\n");
    print_words32(expected_plain, WORDS_PER_BLOCK);
    #endif
    for (int i = 0; i < WORDS_PER_BLOCK; i++) {
        assert(message[i] == expected_plain[i]);
    }
}

int main(void) {
    #ifdef VERBOSE
        printf("============================\n");
        printf("Testing SHACAL2 blockcipher.\n");
        printf("============================\n");
    #endif


    test_SHACAL_2_encrypt();
    printf("All encryption tests passed!!\n");
    test_SHACAL_2_decrypt();
    printf("All decryption tests passed!!\n");
}