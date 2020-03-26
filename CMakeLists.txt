cmake_minimum_required(VERSION 3.10.0)
project(glvs)

set(SRC_FILES
    glvs.cpp
    rapidxml-1.13/rapidxml.hpp
    rapidxml-1.13/rapidxml_print.hpp
    rapidxml-1.13/rapidxml_utils.hpp
    rapidxml-1.13/rapidxml_iterators.hpp
)

add_executable(${PROJECT_NAME}
    ${SRC_FILES}
)
