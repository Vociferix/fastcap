cmake_minimum_required(VERSION 3.16.3)
project(fastcap VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PROJECT_SOURCE_DIR}/cmake/modules")

find_package(Pcap REQUIRED)
find_package(Threads REQUIRED)

add_subdirectory(third_party/CLI11 EXCLUDE_FROM_ALL)
add_subdirectory(third_party/spdlog EXCLUDE_FROM_ALL)

add_subdirectory(src)
