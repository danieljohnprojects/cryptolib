add_library(
    shacal1 SHARED
    src/shacal_1.c
)
target_include_directories(shacal1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(shacal1 PRIVATE IO)
target_compile_options(shacal1 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(shacal1 PRIVATE VERBOSE)

add_executable(
    shacal_1_test
    test/test.c
)
target_link_libraries(shacal_1_test PRIVATE shacal1 IO)
target_compile_options(shacal_1_test PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(shacal_1_test PRIVATE VERBOSE)