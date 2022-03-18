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