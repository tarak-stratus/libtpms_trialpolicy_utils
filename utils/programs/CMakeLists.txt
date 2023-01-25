set(CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_FLAGS 
    "${CMAKE_CXX_FLAGS} -Wall -Wextra" CACHE STRING "Set C++ Compiler Flags" FORCE)

# Add executable
add_executable (util_policynv util_policynv.cpp)

# Link libraries
target_link_libraries (util_policynv LINK_PUBLIC ${LIBTPMS_TPM2})
target_include_directories(util_policynv PUBLIC ${LIBTPMS_TPM2_INCLUDE})
