add_library(
    MD4 SHARED
    src/md4/MD4.c
    src/md4/md4_setup.c
)
target_include_directories(MD4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD4 PRIVATE IO) # Automatically includes the header files, how good is that?! 
target_compile_options(MD4 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(MD4 PUBLIC VERBOSE)

add_executable(
    md4_test
    src/md4/MD4_test.c
)
target_link_libraries(md4_test PRIVATE MD4 IO)
target_compile_options(md4_test PRIVATE "-g" "-Wall" "-Wextra")
    
add_library(
    MD5 SHARED
    src/md5/MD5.c
    src/md5/md5_setup.c
)
target_include_directories(MD5 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD5 PRIVATE IO)
target_compile_options(MD5 PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(MD4 PUBLIC VERBOSE)

add_executable(
    md5_test
    src/md5/MD5_test.c
)
target_link_libraries(md5_test PRIVATE MD5 IO)
target_compile_options(md5_test PRIVATE "-g" "-Wall" "-Wextra")
    
add_library(
    MD2 SHARED
    src/md2/MD2.c
    src/md2/md2_setup.c
)
target_include_directories(MD2 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD2 PRIVATE IO)
target_compile_options(MD2 PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(MD2 PUBLIC VERBOSE)

add_executable(
    md2_test
    src/md2/MD2_test.c
)
target_link_libraries(md2_test PRIVATE MD5 IO)
target_compile_options(md2_test PRIVATE "-g" "-Wall" "-Wextra")
