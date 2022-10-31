cmake_minimum_required(VERSION 3.5)

project(gnutls_client LANGUAGES C)

add_executable(gnutls_client main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c)
target_link_libraries(gnutls_client gnutls curl)
