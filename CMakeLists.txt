cmake_minimum_required(VERSION 3.16)
project(payrisk CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(httplib GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git GIT_TAG v0.18.3)
FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3)
FetchContent_MakeAvailable(httplib json)

find_package(OpenSSL REQUIRED)   # needed for HTTPS calls to PayPal
find_package(Threads REQUIRED)

add_executable(payrisk src/main.cpp)
target_link_libraries(payrisk PRIVATE httplib::httplib nlohmann_json::nlohmann_json
                      OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_compile_definitions(payrisk PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
