add_library(
    aes128 STATIC
    src/AES.c
    include/AES.h
    )
target_include_directories(aes128 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes128 PUBLIC AES128)
target_compile_options(aes128 PRIVATE "-g" "-Wall" "-Wextra")

add_library(
    aes192 STATIC
    src/AES.c
    include/AES.h
)
target_include_directories(aes192 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes192 PUBLIC AES192)
target_compile_options(aes128 PRIVATE "-g" "-Wall" "-Wextra")
target_compile_options(aes192 PRIVATE "-g" "-Wall" "-Wextra")
    
add_library(
    aes256 STATIC
    src/AES.c
    include/AES.h
)
target_include_directories(aes256 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(aes256 PUBLIC AES256)
target_compile_options(aes256 PRIVATE "-g" "-Wall" "-Wextra")