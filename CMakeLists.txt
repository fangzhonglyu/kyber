cmake_minimum_required(VERSION 3.16)
project(Kyber VERSION 3.0)

# Set C standard
set(CMAKE_C_STANDARD 11)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(ref)

# Add compiler flags
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wmissing-prototypes
    -Wredundant-decls
    -Wshadow
    -Wpointer-arith
    -O3
    -fomit-frame-pointer
    -z noexecstack
)

# Gather source files
file(GLOB_RECURSE SOURCES "ref/*.c")

set (KYBER_STRENTHS 512 768 1024)
set (KYBER_K_VALS 2 3 4)

foreach(idx RANGE 0 2)
    list(GET KYBER_STRENTHS ${idx} VARIANT)
    list(GET KYBER_K_VALS ${idx} KYBER_K)
    set(LIBRARY_NAME "Kyber${VARIANT}")
    add_library(${LIBRARY_NAME} ${SOURCES})
    target_compile_definitions(${LIBRARY_NAME} PRIVATE KYBER_K=${KYBER_K})
    target_link_libraries(${LIBRARY_NAME} OpenSSL::SSL OpenSSL::Crypto)
endforeach()


# Create main library
add_library(Kyber ${SOURCES})

# Link OpenSSL to the main library
target_link_libraries(Kyber OpenSSL::SSL OpenSSL::Crypto)

# Enable testing
enable_testing()

# Add test executables
set (TESTS
    "ref/test/test_kyber.c"
    "ref/test/test_speed.c"
    "ref/test/test_vectors.c"
)

foreach(TEST_FILE ${TESTS})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    list(LENGTH VARIANTS num_variants)
    math(EXPR num_variants "${num_variants} - 1")
    # Create an executable for each variant
    foreach(idx RANGE ${num_variants})
        list(GET KYBER_STRENTHS ${idx} VARIANT)
        list(GET KYBER_K_VALS ${idx} KYBER_K)
        set(TARGET_NAME "${TEST_NAME}${VARIANT}")
        add_executable(${TARGET_NAME} ${TEST_FILE})
        # Add the appropriate KYBER_K value
        target_compile_definitions(${TARGET_NAME} PRIVATE KYBER_K=${KYBER_K})
        set (LIBRARY_NAME "Kyber${VARIANT}")
        target_link_libraries(${TARGET_NAME} ${LIBRARY_NAME} OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
    endforeach()
endforeach()