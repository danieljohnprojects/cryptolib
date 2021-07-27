add_library(
    MT19937 SHARED
    src/MT.c
)
target_include_directories(MT19937 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(MT19937 PRIVATE "-g" "-Wall" "-Wextra")

add_executable(
    mt19937_test
    src/MT_test.c
)
target_link_libraries(mt19937_test PRIVATE MT19937)
target_compile_options(mt19937_test PRIVATE "-g" "-Wall" "-Wextra")