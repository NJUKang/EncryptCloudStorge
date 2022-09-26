file(GLOB_RECURSE LIBS *.c)

set(LIBS "${LIBS}")

add_library(ED_LIB SHARED ${LIBS})

file(GLOB_RECURSE CPPLIBS *.cpp)

set(CPPLIBS "${CPPLIBS}")

add_library(ED_CPPLIB SHARED ${CPPLIBS})

# target_link_options(ED_LIB PUBLIC -fPIC -no-pie)