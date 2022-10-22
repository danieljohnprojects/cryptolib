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

#include <Hash.h>
#include <shacal_1.h>

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56

// Reverse the endianness of a uint32
#define MIRROR32(x) ((((x)&0xff) << 24) | (((x)&0xff00) << 8) | (((x)&0xff0000) >> 8) | (((x)&0xff000000) >> 24))

/**
 * @brief Computes the number of 32-bit words needed to store a message of the 
 * given length (in bytes), plus padding and the representation of the message 
 * length.
 * 
 * @param message_length The length of the unpadded message in bytes.
 * @return The length of the corresponding buffer in words.
 */
static size_t determine_padded_length(size_t message_length) {
    size_t x80_padding_length = 1;
    size_t zero_padding_length = ((PAD_REMAINDER - (message_length + x80_padding_length)) % PAD_BLOCK);
    size_t length_length = PAD_BLOCK - PAD_REMAINDER;
    size_t byte_length = message_length + x80_padding_length + zero_padding_length + length_length;

    return byte_length / BYTES_PER_WORD;
}

/**
 * Fills a buffer with the given message and the appropriate padding.
 * 
 * This should be the only part of the code that needs to account for endianness 
 * since we are converting from bytes to ints. We want the first byte of the 
 * message to be the most significant byte of the first word. Since we are working 
 * on a little endian machine we need to reverse the byte order for each word.
 * 
 * @param message A pointer to an array of bytes constituting the message. Note 
 * that this is not necessarily a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param prefix_length The length of the original message  not including any 
 * padding (0 unless performing a length extension attack).
 * @param buffer A pointer to an array that will store the processed message.
 * @param buffer_length The length of the buffer in 32-bit words.
 */
static void 
preprocess(
    const uint8_t *message, 
    size_t message_length,
    size_t prefix_length,
    uint32_t *buffer,
    size_t buffer_length
) {
    for (size_t i = 0; i < buffer_length; i++)
        buffer[i] = 0UL;

    uint8_t *byte_buffer;
    byte_buffer = (uint8_t *) buffer;

    // Copy over the message, one byte at a time.
    size_t i = 0;
    for (; i < message_length; i++) {
        byte_buffer[i] = message[i];
    }
    // Add a single bit at the end.
    byte_buffer[i] = 0x80;
    i++;

    // The first byte of the message needs to be the most significant byte of the first word.
    // Since we are working on a little endian machine we need to reverse the endianness of each word.
    for (size_t j = 0; j < (i + BYTES_PER_WORD - 1) / BYTES_PER_WORD; j++) {
        buffer[j] = MIRROR32(buffer[j]);
    }

    // Store the bit-length of the message at the end of the buffer.
    if (prefix_length)
        prefix_length = BYTES_PER_WORD*determine_padded_length(prefix_length);
    // Need message_length in *bits*
    message_length = (message_length + prefix_length) * 8;
    buffer[buffer_length - 1] = message_length & 0xffffffff;
    buffer[buffer_length - 2] = (message_length & 0xffffffff00000000) >> 32;
}

/**
 * @brief Computes the SHA1 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length of the message measured in bytes.
 * @param prefix_length The length of the original message not including any 
 * padding (0 unless performing a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void 
sha1digest(
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
    shacal_1_key_t key;
    for (size_t i = 0; i < num_key_blocks; i++) {
        initialise_key(processed_message + i*WORDS_PER_KEY, key);
        encrypt(key, digest_buffer);
        for (size_t j = 0; j < WORDS_PER_BLOCK; j++) {
            digest_buffer[j] += previous_digest_state[j];
            previous_digest_state[j] = digest_buffer[j];
        }
    }
}