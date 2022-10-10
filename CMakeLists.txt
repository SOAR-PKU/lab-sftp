cmake_minimum_required(VERSION 3.10)

project(mini-sftp VERSION 1.0)

add_subdirectory(src)

add_executable(client client.c)

target_link_libraries(client sftp)