#pragma once
// Messages are padded out to 16 byte blocks.
#define BLOCK_LENGTH 16
// The checksum occupies a block at the end of the message.
#define CHECKSUM_LENGTH 16

#define STATE_BUFFER_LENGTH 48

#define N_ROUNDS 18
