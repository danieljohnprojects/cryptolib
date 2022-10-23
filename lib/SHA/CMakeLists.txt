add_library(
    SHA1 SHARED
    src/sha1and256.c
    src/preprocessing.c
)
target_include_directories(SHA1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(SHA1 PRIVATE IO shacal1)
target_compile_options(SHA1 PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(SHA1 PRIVATE SHA1)
# target_compile_definitions(SHA1 PRIVATE VERBOSE)

add_library(
    SHA256 SHARED
    src/sha1and256.c
    src/preprocessing.c
)
target_include_directories(SHA256 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(SHA256 PRIVATE IO shacal1)
target_compile_options(SHA256 PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(SHA256 PRIVATE SHA256)
# target_compile_definitions(SHA256 PRIVATE VERBOSE)

add_executable(
    sha1_test
    test/test_sha1.c
)
target_link_libraries(sha1_test PRIVATE SHA1 IO shacal1)
target_compile_options(sha1_test PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(sha1_test PRIVATE VERBOSE)
# target_compile_definitions(sha1_test PRIVATE LONG_TESTS)
        
add_executable(
    sha256_test
    test/test_sha256.c
)
target_link_libraries(sha256_test PRIVATE SHA256 IO shacal2)
target_compile_options(sha256_test PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(sha256_test PRIVATE VERBOSE)
# target_compile_definitions(sha256_test PRIVATE LONG_TESTS)
        