include_directories(${CMAKE_SOURCE_DIR})

add_executable(server ${CMAKE_SOURCE_DIR}/src/server.cpp)

target_link_libraries(server cryptoTools pthread ED_LIB ED_CPPLIB isal_crypto glib-2.0 ssl crypto gmp gmpxx)

target_include_directories(server PUBLIC
                            "${PROJECT_BINARY_DIR}"
                            "${PROJECT_SOURCE_DIR}/lib"
                            )

target_compile_options(server PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -fpermissive -DNO_IPO=TRUE)

add_executable(client ${CMAKE_SOURCE_DIR}/src/client.cpp)

target_link_libraries(client cryptoTools pthread ED_LIB ED_CPPLIB isal_crypto glib-2.0 ssl crypto gmp gmpxx)

target_include_directories(client PUBLIC
                            "${PROJECT_BINARY_DIR}"
                            "${PROJECT_SOURCE_DIR}/lib"
                            )

target_compile_options(client PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -fpermissive -DNO_IPO=TRUE)