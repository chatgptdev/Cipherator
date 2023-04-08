cmake_minimum_required(VERSION 3.16)
project(Cipherator)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# If you want to enable additional warnings and treat them as errors, uncomment the following lines
# if(MSVC)
#     add_compile_options(/W4 /WX)
# else()
#     add_compile_options(-Wall -Wextra -pedantic -Werror)
# endif()

# Link against the static C runtime
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(cipherator
    main.cpp
    crypto_tool.h
    crypto_tool.cpp
    encryption.h
    encryption.cpp
    key_management.h
    key_management.cpp
    secure_vector.h
)

target_link_libraries(cipherator bcrypt)

