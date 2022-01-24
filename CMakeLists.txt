cmake_minimum_required(VERSION 3.13)  # CMake version check
project(simple_example)               # Create project "simple_example"
set(CMAKE_C_STANDARD 11) 

add_executable(out debugger.c find_symbol.c)