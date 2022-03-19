#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "MD2.h"

void test_MD2digest()
{
    uint8_t message[81];
    for (size_t i = 0; i < 80; i++)
        message[i] = 0x00;
    uint8_t digest_buffer[DIGEST_LENGTH];
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;

    printf("Computing hash of empty string:\n");
    md2digest(message, 0, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x83);
    assert (digest_buffer[1] == 0x50);
    printf("\n");

    printf("Computing hash of \"a\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    message[0] = 'a';
    md2digest(message, 1, digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x32);
    assert (digest_buffer[1] == 0xec);
    printf("\n");

    printf("Computing hash of \"abc\":\n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abc");
    md2digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xda);
    assert (digest_buffer[1] == 0x85);
    printf("\n");

    printf("Computing hash of \"message digest\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "message digest");
    md2digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xab);
    assert (digest_buffer[1] == 0x4f);
    printf("\n");

    printf("Computing hash of \"abcdefghijklmnopqrstuvwxyz\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "abcdefghijklmnopqrstuvwxyz");
    md2digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0x4e);
    assert (digest_buffer[1] == 0x8d);
    printf("\n");

    printf("Computing hash of \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    md2digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xda);
    assert (digest_buffer[1] == 0x33);
    printf("\n");

    printf("Computing hash of \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\": \n");
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = 0x00;
    strcpy((char *) message, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    md2digest(message, strlen((char *) message), digest_buffer);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    assert (digest_buffer[0] == 0xd5);
    assert (digest_buffer[1] == 0x97);
    printf("\n");
}

int main()
{
    printf("Testing hashes against test vectors...\n");
    test_MD2digest();
    printf("Tests passed!\n\n");
}