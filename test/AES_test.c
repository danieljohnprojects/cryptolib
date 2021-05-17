#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <AES.h>

/**
 * Runs tests for the AES key scheduler.
 */
void test_key_schedule()
{
    #ifdef AES128
    uint32_t initial_key[] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t expected_answer[ROUND_KEYS + 1][WORDS_PER_ROUND_KEY] = {
        {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f}, //00
        {0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe}, //01
        {0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe}, //02
        {0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41}, //03
        {0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd}, //04
        {0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa}, //05
        {0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b}, //06
        {0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026}, //07
        {0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2}, //08
        {0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e}, //09
        {0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5},  //10
    };
    #endif
    #ifdef AES192
    uint32_t initial_key[] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617};
    uint32_t expected_answer[ROUND_KEYS + 1][WORDS_PER_ROUND_KEY] = {
        {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f}, //00
        {0x10111213, 0x14151617, 0x5846f2f9, 0x5c43f4fe}, //01
        {0x544afef5, 0x5847f0fa, 0x4856e2e9, 0x5c43f4fe}, //02
        {0x40f949b3, 0x1cbabd4d, 0x48f043b8, 0x10b7b342}, //03
        {0x58e151ab, 0x04a2a555, 0x7effb541, 0x6245080c}, //04
        {0x2ab54bb4, 0x3a02f8f6, 0x62e3a95d, 0x66410c08}, //05
        {0xf5018572, 0x97448d7e, 0xbdf1c6ca, 0x87f33e3c}, //06
        {0xe5109761, 0x83519b69, 0x34157c9e, 0xa351f1e0}, //07
        {0x1ea0372a, 0x99530916, 0x7c439e77, 0xff12051e}, //08
        {0xdd7e0e88, 0x7e2fff68, 0x608fc842, 0xf9dcc154}, //09
        {0x859f5f23, 0x7a8d5a3d, 0xc0c02952, 0xbeefd63a}, //10
        {0xde601e78, 0x27bcdf2c, 0xa223800f, 0xd8aeda32}, //11
        {0xa4970a33, 0x1a78dc09, 0xc418c271, 0xe3a41d5d}, //12
    };
    #endif
    #ifdef AES256
    uint32_t initial_key[] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};
    uint32_t expected_answer[ROUND_KEYS + 1][WORDS_PER_ROUND_KEY] = {
        {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f},  //00
        {0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f}, //01
        {0xa573c29f, 0xa176c498, 0xa97fce93, 0xa572c09c}, //02
        {0x1651a8cd, 0x0244beda, 0x1a5da4c1, 0x0640bade}, //03
        {0xae87dff0, 0x0ff11b68, 0xa68ed5fb, 0x03fc1567}, //04
        {0x6de1f148, 0x6fa54f92, 0x75f8eb53, 0x73b8518d}, //05
        {0xc656827f, 0xc9a79917, 0x6f294cec, 0x6cd5598b}, //06
        {0x3de23a75, 0x524775e7, 0x27bf9eb4, 0x5407cf39}, //07
        {0x0bdc905f, 0xc27b0948, 0xad5245a4, 0xc1871c2f}, //08
        {0x45f5a660, 0x17b2d387, 0x300d4d33, 0x640a820a}, //09
        {0x7ccff71c, 0xbeb4fe54, 0x13e6bbf0, 0xd261a7df}, //10
        {0xf01afafe, 0xe7a82979, 0xd7a5644a, 0xb3afe640}, //11
        {0x2541fe71, 0x9bf50025, 0x8813bbd5, 0x5a721c0a}, //12
        {0x4e5a6699, 0xa9f24fe0, 0x7e572baa, 0xcdf8cdea}, //13
        {0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36}, //14
    };
    #endif

    AES_key key_schedule;
    initialise_key(initial_key, &key_schedule);
    
    // Check that subsequent derived keys
    for (int round = 0; round < ROUND_KEYS + 1; round++)
        for (int word = 0; round < WORDS_PER_ROUND_KEY; word++)
            assert(key_schedule.schedule[round][word] == expected_answer[round][word]);
}

int main(void)
{
    test_key_schedule();
    printf("Key schedule test passed!\n");
}