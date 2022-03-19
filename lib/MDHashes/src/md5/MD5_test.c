#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "MD5.h"

void test_MD5digest()
{
    uint8_t message[81];
    for (size_t i = 0; i < 81; i++)
        message[i] = 0x00;
    uint8_t digest_buffer[DIGEST_LENGTH];
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;

    printf("Computing hash of empty string:\n");
    digest(message, 0, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xd4);
    assert (digest_buffer[1] == 0x1d);
    printf("\n");

    printf("Computing hash of \"a\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    message[0] = 'a';
    digest(message, 1, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x0c);
    assert (digest_buffer[1] == 0xc1);
    printf("\n");

    printf("Computing hash of \"abc\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abc");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x90);
    assert (digest_buffer[1] == 0x01);
    printf("\n");

    printf("Computing hash of \"message digest_buffer\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "message digest");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xf9);
    assert (digest_buffer[1] == 0x6b);
    printf("\n");

    printf("Computing hash of \"abcdefghijklmnopqrstuvwxyz\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abcdefghijklmnopqrstuvwxyz");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xc3);
    assert (digest_buffer[1] == 0xfc);
    printf("\n");

    printf("Computing hash of \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xd1);
    assert (digest_buffer[1] == 0x74);
    printf("\n");

    printf("Computing hash of \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x57);
    assert (digest_buffer[1] == 0xed);
    printf("\n");
}

int main()
{
    printf("Testing hashes against test vectors...\n");
    test_MD5digest();
    printf("Tests passed!\n\n");
}