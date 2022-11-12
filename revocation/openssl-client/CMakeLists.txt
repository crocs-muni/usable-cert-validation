cmake_minimum_required(VERSION 3.5)

project(openssl_client LANGUAGES C)

add_executable(openssl_client main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c)
target_link_libraries(openssl_client ssl crypto curl)
