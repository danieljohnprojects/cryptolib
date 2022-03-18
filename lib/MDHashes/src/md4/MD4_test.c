#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "MD4.h"

// void test_determine_padded_length()
// {
//     size_t i = 0;
//     assert (determine_padded_length(i) == 16);
//     for (i = 0; i < 56; i++)
//         assert (determine_padded_length(i) == 16);
//     for (i = 56; i < 64+56; i++)
//         assert (determine_padded_length(i) == 32);
//     for (i = 64+56; i < 2*64 + 56; i++)
//         assert (determine_padded_length(i) == 48);
// }

// void test_preprocess()
// {
//     uint8_t message[80];
//     message[0] = 'a';
//     message[1] = 'b';
//     message[2] = 'c';
//     message[3] = 'd';
//     message[4] = 'e';
//     message[5] = 'f';
//     message[6] = 'g';
//     message[7] = 'h';
//     message[8] = 'i';
//     message[9] = 'j';

//     size_t n = determine_padded_length(10);
//     uint32_t buffer[n];
//     for(size_t i = 0; i < n; i++)
//         buffer[i] = 0;
    
//     preprocess(message, 10, buffer, n);
// }

void test_MD4digest()
{
    uint8_t message[81];
    for (size_t i = 0; i < 80; i++)
        message[i] = 0x00;
    uint8_t digest_buffer[DIGEST_LENGTH];
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;

    printf("Computing hash of empty string:\n");
    digest(message, 0, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x31);
    assert (digest_buffer[1] == 0xd6);
    printf("\n");

    printf("Computing hash of \"a\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    message[0] = 'a';
    digest(message, 1, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xbd);
    assert (digest_buffer[1] == 0xe5);
    printf("\n");

    printf("Computing hash of \"abc\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abc");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xa4);
    assert (digest_buffer[1] == 0x48);
    printf("\n");

    printf("Computing hash of \"message digest\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "message digest");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xd9);
    assert (digest_buffer[1] == 0x13);
    printf("\n");

    printf("Computing hash of \"abcdefghijklmnopqrstuvwxyz\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abcdefghijklmnopqrstuvwxyz");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xd7);
    assert (digest_buffer[1] == 0x9e);
    printf("\n");

    printf("Computing hash of \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x04);
    assert (digest_buffer[1] == 0x3f);
    printf("\n");

    printf("Computing hash of \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xe3);
    assert (digest_buffer[1] == 0x3b);
    printf("\n");
}

int main()
{
    // printf("Testing determine_padded_length function...\n");
    // test_determine_padded_length();
    // printf("Tests passed!\n\n");

    // test_preprocess();

    printf("Testing hashes against test vectors...\n");
    test_MD4digest();
    printf("Tests passed!\n\n");
}