/**
 * @file sha1.c
 * @brief An implementation of the SHA1 hash function. 
 * 
 * The SHA1 hash takes in an arbitrary length message and computes a 160-bit 
 * value. See the description given in RFC 3174:
 * http://www.faqs.org/rfcs/rfc3174.html
 * or in the FIPS publication:
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * for full details.
 * 
 * We make use of the SHACAL-1 block cipher, emphasising the use of the 
 * Davies-Meyer construction.
 * 
 * We do not initialise the digest buffer to the correct values. This makes it 
 * more convenient to perform length extension attacks but passes the burden of
 * initialisation to the user when computing a regular hash.
 * 
 * We will always assume that messages are strings of bytes, rather than of 
 * bits.
 */
#ifdef VERBOSE
#include <stdio.h>
#include <IO.h>
#endif

#include "preprocessing.h"
#ifdef SHA1
#include <shacal_1.h>
#include <SHA1.h>
#endif
#ifdef SHA256
#include <shacal_2.h>
#include <SHA256.h>
#endif


/**
 * @brief Computes the digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length of the message measured in bytes.
 * @param prefix_length The length of the original message not including any 
 * padding (0 unless performing a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void
#ifdef SHA1
sha1digest(
#endif
#ifdef SHA256
sha256digest(
#endif
    const uint8_t *message, 
    size_t message_length,
    size_t prefix_length,
    block_t digest_buffer
) {
    #ifdef VERBOSE
    printf("Recieved message of length %ld bytes.\n", message_length);
    #endif
    size_t buffer_length = determine_padded_length(message_length);
    #ifdef VERBOSE
    printf("Creating buffer of length %ld words to hold processed message.\n", buffer_length);
    #endif
    uint32_t processed_message[buffer_length];

    preprocess(message, message_length, prefix_length, processed_message, buffer_length);
    #ifdef VERBOSE
    printf("Original message:\n");
    print_bytes(message, message_length);
    printf("Processed message:\n");
    print_words32(processed_message, buffer_length);
    #endif

    // We need to add the previous digest state onto the encrypted block so make a copy of it now.
    block_t previous_digest_state;
    for (size_t i = 0; i < WORDS_PER_BLOCK; i++) {
        previous_digest_state[i] = digest_buffer[i];
    }

    // Split the message into blocks of length 512 bits and use these to key the SHACAL-1 block cipher.
    size_t num_key_blocks = buffer_length / WORDS_PER_KEY;
    #ifdef SHA1
    shacal_1_key_t key;
    #endif
    #ifdef SHA256
    shacal_2_key_t key;
    #endif
    for (size_t i = 0; i < num_key_blocks; i++) {
        initialise_key(processed_message + i*WORDS_PER_KEY, key);
        encrypt(key, digest_buffer);
        for (size_t j = 0; j < WORDS_PER_BLOCK; j++) {
            digest_buffer[j] += previous_digest_state[j];
            previous_digest_state[j] = digest_buffer[j];
        }
    }
}