add_executable(
    AES128_test
    AES_test.c
)
target_link_libraries(AES128_test PRIVATE aes128)
target_compile_options(AES128_test PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    AES192_test
    AES_test.c
)
target_link_libraries(AES192_test PRIVATE aes192)
target_compile_options(AES192_test PRIVATE "-g" "-Wall" "-Wextra")
    
add_executable(
    AES256_test
    AES_test.c
)
target_link_libraries(AES256_test PRIVATE aes256)
target_compile_options(AES256_test PRIVATE "-g" "-Wall" "-Wextra")