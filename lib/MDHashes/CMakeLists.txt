add_library(
    MD4 SHARED
    src/MD4.c
    src/helper_functions.c
)
target_include_directories(MD4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(MD4 PUBLIC MD4)
target_compile_options(MD4 PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    md4_test
    src/MD4_test.c
)
target_link_libraries(md4_test PRIVATE MD4)
target_compile_options(md4_test PRIVATE "-g" "-Wall" "-Wextra")