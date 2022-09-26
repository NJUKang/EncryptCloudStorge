cmake_minimum_required(VERSION 3.24)

project(cryptoToolsTest)

set(CMAKE_C_FLAGS "-Wall -Wfatal-errors")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -DNO_IPO=TRUE")	
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")

add_subdirectory(src bin)


add_subdirectory(lib)


