add_library(
    IO SHARED
    src/IO.c
)
target_include_directories(IO PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(IO PRIVATE "-g" "-Wall" "-Wextra")