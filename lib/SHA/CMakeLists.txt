add_library(
    SHA1 SHARED
    src/SHA1.c
)
target_include_directories(SHA1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(SHA1 PRIVATE IO)
target_compile_options(SHA1 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(SHA1 PRIVATE VERBOSE)

add_executable(
    sha_test
    test/test.c
)
target_link_libraries(sha_test PRIVATE SHA1 IO)
target_compile_options(sha_test PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(sha_test PRIVATE VERBOSE)
        