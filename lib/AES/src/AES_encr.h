#pragma once

#include <AES.h>

void encryption_round(block_t *in, block_t *out, bool final);