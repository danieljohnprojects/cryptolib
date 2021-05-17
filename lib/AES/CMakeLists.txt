add_library(
    aes128 SHARED
    src/AES_ks.c
    src/AES_ks.h
    )
target_include_directories(aes128 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes128 PUBLIC AES128)
target_compile_options(aes128 PRIVATE "-g" "-Wall" "-Wextra")

add_library(
    aes192 SHARED
    src/AES_ks.c
    src/AES_ks.h
)
target_include_directories(aes192 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes192 PUBLIC AES192)
target_compile_options(aes192 PRIVATE "-g" "-Wall" "-Wextra")
    
add_library(
    aes256 SHARED
    src/AES_ks.c
    src/AES_ks.h
)
target_include_directories(aes256 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes256 PUBLIC AES256)
target_compile_options(aes256 PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    aes128_ks_test
    src/AES_ks_test.c
)
target_link_libraries(aes128_ks_test PRIVATE aes128)
target_compile_options(aes128_ks_test PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    aes192_ks_test
    src/AES_ks_test.c
)
target_link_libraries(aes192_ks_test PRIVATE aes192)
target_compile_options(aes192_ks_test PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    aes256_ks_test
    src/AES_ks_test.c
)
target_link_libraries(aes256_ks_test PRIVATE aes256)
target_compile_options(aes256_ks_test PRIVATE "-g" "-Wall" "-Wextra")