cmake_minimum_required(VERSION 3.16.3)
set(CMAKE_CXX_STANDARD 20)

OPTION(ENABLE_TESTING "Build the library with tests" OFF)
OPTION(ENABLE_EXAMPLES "Build examples" OFF)

set(LIBRARY_NAME HashLibCpp)

project(${LIBRARY_NAME})

include_directories(${PROJECT_SOURCE_DIR}/include)

# Make sure that __uint128_t is available
if(("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
    add_library(${LIBRARY_NAME} SHARED
            src/sha2.cpp
            src/sha224.cpp
            src/sha256.cpp
            src/sha384.cpp
            src/sha512.cpp)
else()
    message(WARNING "Couldn't compile sha384.cpp and sha512.cpp, GNU or Clang needed, you compiled with ${CMAKE_CXX_COMPILER_ID}")
    add_library(${LIBRARY_NAME} SHARED
            src/sha2.cpp
            src/sha224.cpp
            src/sha256.cpp)
endif() # STREQUAL "GNU OR Clang"

# Set maximum warnings level depending on compiler.
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    target_compile_options(${LIBRARY_NAME} PRIVATE
            -Weverything
            -Wno-c++98-compat
            -Wno-c++98-compat-pedantic
            -Wno-padded
            -Wno-shadow
            -Wno-weak-vtables
            -pedantic
            -pedantic-errors)
else()
    set_target_properties(${LIBRARY_NAME} PROPERTIES
            COMPILE_FLAGS "-Wall"
            COMPILE_FLAGS "-Wextra"
            COMPILE_FLAGS "-Waddress"
            COMPILE_FLAGS "-Warray-bounds"
            COMPILE_FLAGS "-Wbuiltin-macro-redefined"
            COMPILE_FLAGS "-Wconversion"
            COMPILE_FLAGS "-Wctor-dtor-privacy"
            COMPILE_FLAGS "-Winit-self"
            COMPILE_FLAGS "-Wnon-virtual-dtor"
            COMPILE_FLAGS "-Wold-style-cast"
            COMPILE_FLAGS "-Woverloaded-virtual"
            COMPILE_FLAGS "-Wsuggest-attribute=const"
            COMPILE_FLAGS "-Wsuggest-attribute=noreturn"
            COMPILE_FLAGS "-Wsuggest-attribute=pure"
            COMPILE_FLAGS "-Wswitch"
            COMPILE_FLAGS "-Wunreachable-code"
            COMPILE_FLAGS "-pedantic"
            COMPILE_FLAGS "-pedantic-errors")
endif() # STREQUAL "Clang"

set_target_properties(${LIBRARY_NAME} PROPERTIES VERSION 0.0.1)

function(enable_all_warnings TARGET)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        target_compile_options(${TARGET} PRIVATE
                -Weverything
                -Wno-c++98-compat
                -Wno-c++98-compat-pedantic
                -Wno-padded
                -Wno-shadow
                -Wno-weak-vtables
                -pedantic
                -pedantic-errors)
    endif()
endfunction()

if(ENABLE_EXAMPLES)
    add_executable(sha224_argv examples/sha224_argv.cpp)
    enable_all_warnings(sha224_argv)
    target_link_libraries(sha224_argv ${LIBRARY_NAME})

    add_executable(sha256_argv examples/sha256_argv.cpp)
    enable_all_warnings(sha256_argv)
    target_link_libraries(sha256_argv ${LIBRARY_NAME})

    if(("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
        add_executable(sha384_argv examples/sha384_argv.cpp)
        enable_all_warnings(sha384_argv)
        target_link_libraries(sha384_argv ${LIBRARY_NAME})

        add_executable(sha512_argv examples/sha512_argv.cpp)
        enable_all_warnings(sha512_argv)
        target_link_libraries(sha512_argv ${LIBRARY_NAME})
    endif() # STREQUAL "GNU OR Clang"
else()
    #############################################################
    #                  Add your .cpp files here                 #
    #############################################################
    # add_executable(<EXECUTABLE NAME> <PATH TO YOUR CPP FILE>) #

    #############################################################
    #            Link library to your executable here           #
    #############################################################
    # target_link_libraries(<EXECUTABLE NAME> ${LIBRARY_NAME})  #
endif(ENABLE_EXAMPLES)

if(ENABLE_TESTING)
    enable_testing()
    add_executable(test_sha224 tests/test_sha224.cpp)
    target_link_libraries(test_sha224 ${LIBRARY_NAME})
    add_test(NAME sha224 COMMAND test_sha224)


    add_executable(test_sha256 tests/test_sha256.cpp)
    target_link_libraries(test_sha256 ${LIBRARY_NAME})
    add_test(NAME sha256 COMMAND test_sha256)


    add_executable(test_sha384 tests/test_sha384.cpp)
    target_link_libraries(test_sha384 ${LIBRARY_NAME})
    add_test(NAME sha384 COMMAND test_sha384)


    add_executable(test_sha512 tests/test_sha512.cpp)
    target_link_libraries(test_sha512 ${LIBRARY_NAME})
    add_test(NAME sha512 COMMAND test_sha512)

endif(ENABLE_TESTING)

install(
        TARGETS
        ${LIBRARY_NAME}
        LIBRARY DESTINATION lib COMPONENT runtime
        ARCHIVE DESTINATION lib COMPONENT development)

install(
        DIRECTORY
        include/
        DESTINATION include
        COMPONENT development
        PATTERN "detail" EXCLUDE)