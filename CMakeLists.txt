cmake_minimum_required(VERSION 3.20)
project(CANXLKeyDistribution VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# KBKDF/HKDF are provided by OpenSSL 3's EVP_KDF API.
find_package(OpenSSL REQUIRED)
if(OPENSSL_VERSION VERSION_LESS 3.0)
    message(FATAL_ERROR "OpenSSL >= 3.0 gerekli (EVP_KDF KBKDF icin). Bulunan: ${OPENSSL_VERSION}")
endif()

# Sinifi bir kez bir kutuphaneye derle; hem main hem test buna baglanir.
add_library(cankeydist_lib STATIC src/CANKeyDistrb.cpp)
target_include_directories(cankeydist_lib PUBLIC inc)
target_link_libraries(cankeydist_lib PUBLIC OpenSSL::Crypto)

# Demo calistirilabiliri
add_executable(cankeydist src/main.cpp)
target_link_libraries(cankeydist PRIVATE cankeydist_lib)

# Test calistirilabiliri
add_executable(cankeydist_test test/test_keydist.cpp)
target_link_libraries(cankeydist_test PRIVATE cankeydist_lib)

enable_testing()
add_test(NAME keydist_tests COMMAND cankeydist_test)

# Benchmark calistirilabilirleri (ayri dosyalar)
add_executable(cankeydist_bench_ops bench/bench_operations.cpp)
target_include_directories(cankeydist_bench_ops PRIVATE bench)
target_link_libraries(cankeydist_bench_ops PRIVATE cankeydist_lib)

add_executable(cankeydist_bench_scenarios bench/bench_scenarios.cpp)
target_include_directories(cankeydist_bench_scenarios PRIVATE bench)
target_link_libraries(cankeydist_bench_scenarios PRIVATE cankeydist_lib)
