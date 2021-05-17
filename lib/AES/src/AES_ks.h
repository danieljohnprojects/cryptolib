#include <stdint.h>
#include <AES.h>

uint32_t rotword(uint32_t word);
uint32_t subword(uint32_t word);
void initialise_key(const uint32_t initial_key[WORDS_PER_KEY], AES_key *expanded_key);