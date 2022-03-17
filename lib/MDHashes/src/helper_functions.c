#include <stdint.h>
#include <stdio.h>

#include "helper_functions.h"
#include "constants_global.h"
#ifdef MD2
    #include "constants_MD2.h"
#endif
#ifdef MD4
    #include "constants_MD4.h"
#endif
#ifdef MD5
    #include "constants_MD5.h"
#endif

/**
 * @brief Prints the supplied digest in hex.
 * 
 * @param digest The value to print.
 */
void print_digest(const uint8_t digest[DIGEST_LENGTH])
{
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
    {
        if (i > 0 && i%4==0)
            printf(" ");
        printf("%02x", digest[i]);
    }
    printf("\n");
}


/**
 * @brief Computes the number of 32-bit words needed to store a message of the 
 * given length (in bytes), plus padding and the representation of the message 
 * length.
 * 
 * @param message_length The length of the unpadded message in butes.
 * @return The length of the corresponding buffer in words.
 */
size_t determine_padded_length(size_t message_length)
#if defined MD4 || MD5
{
    size_t padding_length = ((PAD_REMAINDER - message_length - 1) % PAD_BLOCK) + 1;
    size_t length_length = PAD_BLOCK - PAD_REMAINDER;
    size_t byte_length = message_length + padding_length + length_length;

    return byte_length / 4;
}
#endif


/**
 * Fills a buffer with the given message and the appropriate padding.
 * 
 * @param message A pointer to an array of bytes constituting the message. Note 
 * that this is not necesarilly a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param buffer A pointer to an array that will store the processed 
 * message.
 * @param buffer_length The length of the buffer in 32-bit words.
 */
void preprocess(const uint8_t *message, 
                size_t message_length,
                uint32_t *buffer,
                size_t buffer_length)
#if defined MD4 || MD5
{
    for (size_t i = 0; i < buffer_length; i++)
        buffer[i] = 0UL;

    uint8_t *byte_buffer;
    byte_buffer = (uint8_t *) buffer;
    // Copy over the message
    size_t i = 0;
    for (; i < message_length; i++) {
        byte_buffer[i] = message[i];
    }
    byte_buffer[i] = 0x80;

    uint64_t *length_buffer = (uint64_t *) (&(buffer[buffer_length - 2]));
    *length_buffer = message_length * 8; // Length in *bits*
}
// #elif defined MD2
// {

// }
#endif


/**
 * @brief Initialises the digest to the starting values shown in Step 3.
 * 
 * @param digest A pointer to the digest to be initialised.
 */
void init_digest(uint8_t digest[DIGEST_LENGTH])
#if defined MD4 || MD5
{
    digest[0] = 0x01;
    digest[1] = 0x23;
    digest[2] = 0x45;
    digest[3] = 0x67;
    digest[4] = 0x89;
    digest[5] = 0xab;
    digest[6] = 0xcd;
    digest[7] = 0xef;
    digest[8] = 0xfe;
    digest[9] = 0xdc;
    digest[10] = 0xba;
    digest[11] = 0x98;
    digest[12] = 0x76;
    digest[13] = 0x54;
    digest[14] = 0x32;
    digest[15] = 0x10;
}
#endif


