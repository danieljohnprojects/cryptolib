add_executable(
    AES128_test
    AES_test.c
)
target_link_libraries(AES128_test PRIVATE aes128)

add_executable(
    AES192_test
    AES_test.c
)
target_link_libraries(AES192_test PRIVATE aes192)

add_executable(
    AES256_test
    AES_test.c
)
target_link_libraries(AES256_test PRIVATE aes256)