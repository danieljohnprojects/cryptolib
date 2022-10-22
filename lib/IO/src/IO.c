#include <IO.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Prints the supplied bytes in hex, separating on four byte boundaries.
 * 
 * @param bytes A pointer to the bytes to print
 * @param n The number of bytes to print
 */
void print_bytes(const uint8_t *bytes, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        if (i > 0 && i%4==0)
            printf(" ");
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/**
 * @brief Prints the supplied words as little-endian 32-bit integers.
 * 
 * @param words A pointer to the words to print
 * @param n The number of words to print
 */
void print_words32(const uint32_t *words, size_t n)
{
    size_t row_length = 8;
    size_t rows = (n + (row_length - 1)) / row_length;
    size_t rem = rows * row_length - n;

    for (size_t i = 0; i < n; i++) {
        printf("%08x ", words[i]);
        if ((i+1) % row_length == 0 && i != n-1) {
            printf("\n");
        }
    }
    for (size_t i = 0; i < rem; i++) {
        printf("........ ");
    }
    printf("\n");
}