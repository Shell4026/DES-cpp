cmake_minimum_required(VERSION 3.8)

project(DES LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB SRC "src/*.cpp")

add_executable(DES main.cpp ${SRC})

target_include_directories(DES PUBLIC "${CMAKE_SOURCE_DIR}/include")