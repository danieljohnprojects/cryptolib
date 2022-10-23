#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <IO.h>
#include <shacal_1.h>

void test_SHACAL_1_encrypt() {
    block_t message = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    };

    #ifdef VERBOSE
    printf("Encrypting message:\n");
    print_words32(message, 5);
    #endif

    // Can use the test vectors of SHA1, just need to subtract of initial state first.
    block_t expected_cipher = {
        0xa9993e36 - 0x67452301,
        0x4706816a - 0xefcdab89,
        0xba3e2571 - 0x98badcfe,
        0x7850c26c - 0x10325476,
        0x9cd0d89d - 0xc3d2e1f0,
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
    shacal_1_key_t key_schedule;
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

void test_SHACAL_1_decrypt() {
    // Use SHA1 test vector minus the input initialisation.
    block_t message = {
        0xa9993e36 - 0x67452301,
        0x4706816a - 0xefcdab89,
        0xba3e2571 - 0x98badcfe,
        0x7850c26c - 0x10325476,
        0x9cd0d89d - 0xc3d2e1f0,
    };
    block_t expected_plain = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    };
    // uint8_t key[] = {
    //     0x80, 0x63, 0x62, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    // };
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
    shacal_1_key_t key_schedule;
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
        printf("Testing SHACAL1 blockcipher.\n");
        printf("============================\n");
    #endif


    test_SHACAL_1_encrypt();
    printf("All encryption tests passed!!\n");
    test_SHACAL_1_decrypt();
    printf("All decryption tests passed!!\n");
}