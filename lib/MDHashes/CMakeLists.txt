add_library(
    MD2 SHARED
    src/md2/MD2.c
)
target_include_directories(MD2 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD2 PRIVATE IO)
target_compile_options(MD2 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(MD2 PRIVATE VERBOSE)
    
add_library(
    MD4 SHARED
    src/md4/MD4.c
)
target_include_directories(MD4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD4 PRIVATE IO) # Automatically includes the header files, how good is that?! 
target_compile_options(MD4 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(MD4 PRIVATE VERBOSE)
    
add_library(
    MD5 SHARED
    src/md5/MD5.c
)
target_include_directories(MD5 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(MD5 PRIVATE IO)
target_compile_options(MD5 PRIVATE "-g" "-Wall" "-Wextra")
# target_compile_definitions(MD5 PRIVATE VERBOSE)
    
add_executable(
    md_test
    test/test.c
)
target_link_libraries(md_test PRIVATE MD2 MD4 MD5 IO)
target_compile_options(md_test PRIVATE "-g" "-Wall" "-Wextra")
target_compile_definitions(md_test PRIVATE VERBOSE)
        