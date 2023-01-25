# CMakeLists files in this project can
cmake_minimum_required (VERSION 3.1.1)
project (tpm2_utils)

# libtpms-tpm2 related libs and includes
find_library(LIBTPMS_TPM2 tpms_tpm2 HINTS ${CMAKE_SOURCE_DIR}/../build/src/.libs/)
set(LIBTPMS_TPM2_INCLUDE
    ${CMAKE_SOURCE_DIR}/../src/tpm2
    ${CMAKE_SOURCE_DIR}/../src/tpm2/crypto/
    ${CMAKE_SOURCE_DIR}/../src/tpm2/crypto/openssl
)

add_compile_definitions(
    TPM_POSIX
    ALG_ECDSA
    ALG_RSA
)
add_subdirectory (programs)
