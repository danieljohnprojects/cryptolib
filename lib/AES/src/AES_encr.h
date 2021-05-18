#pragma once

#include <AES.h>

block_t encryption_round(block_t *input, bool final);