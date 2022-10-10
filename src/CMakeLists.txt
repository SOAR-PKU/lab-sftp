aux_source_directory(. DIR_LIB_SRCS)

find_package(OpenSSL REQUIRED)

add_library (sftp SHARED ${DIR_LIB_SRCS})

target_include_directories(sftp PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(sftp OpenSSL::Crypto)