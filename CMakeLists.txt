cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 20)

OPTION(ENABLE_TESTING "Build the library with tests" OFF)
OPTION(ENABLE_EXAMPLES "Build examples" ON)

set(LIBRARY_NAME HashLibCpp)

project(${LIBRARY_NAME})

include_directories(${PROJECT_SOURCE_DIR}/include)

add_library(${LIBRARY_NAME} SHARED
        src/sha2.cpp
        src/sha256.cpp)

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
endif()

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
    # Hello World example
    add_executable(1-hello
            examples/1.hello.cpp)

    enable_all_warnings(1-hello)

    target_link_libraries(1-hello ${LIBRARY_NAME})
endif(ENABLE_EXAMPLES)

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