cmake_minimum_required(VERSION 3.10.2)

# 项目声明
project(securityguard)

# 设置C++标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译选项
add_compile_options(
    -Wall
    -Wextra
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -Wno-unused-parameter
    -Wno-unused-variable
)

# 定义Android平台
if(ANDROID)
    # 针对不同架构设置优化选项
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        add_compile_options(-O3 -fomit-frame-pointer)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        add_compile_options(-O3 -fomit-frame-pointer)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_compile_options(-O3 -fomit-frame-pointer)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686")
        add_compile_options(-O3 -fomit-frame-pointer)
    endif()

    # 安全相关的编译选项
    add_compile_options(
        -fstack-protector-strong    # 堆栈保护
    )
endif()

# 查找Android日志库
find_library(log-lib log REQUIRED)

# 查找Zlib（用于可能的压缩操作）
find_library(zlib-lib z)

# 定义源文件
set(NATIVE_SOURCES
    signature_verify.cpp
    xposed_detector.cpp
    jni_interface.cpp
    security_checker.cpp
    apk_parser.cpp
)

# 创建Native库
add_library(
    securityguard
    SHARED
    ${NATIVE_SOURCES}
)

# 头文件目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 链接库
target_link_libraries(
    securityguard
    ${log-lib}
)

# 如果找到zlib，也链接它
if(zlib-lib)
    target_link_libraries(securityguard ${zlib-lib})
endif()

# 链接dl库（用于dlopen等函数）
if(ANDROID)
    target_link_libraries(securityguard dl)
endif()

# 优化链接选项
target_link_options(securityguard
    PRIVATE
    -Wl,--gc-sections         # 移除未使用的代码段
    -Wl,--strip-all           # 移除符号信息
    -Wl,--as-needed           # 只链接需要的库
)

# 定义版本信息
set_target_properties(securityguard PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
)

# 添加OpenSSL支持（如果可用）
# 注意：需要在项目中集成OpenSSL库
# 这里假设已经将OpenSSL编译为静态库

# 检查是否存在OpenSSL库文件
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/openssl/libcrypto.a")
    add_library(crypto STATIC IMPORTED)
    set_target_properties(crypto PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/openssl/libcrypto.a"
    )

    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/openssl/include")
    target_link_libraries(securityguard crypto)
else()
    # 如果没有OpenSSL，提供替代的哈希实现
    message(STATUS "OpenSSL not found, using fallback hash implementation")
    add_compile_definitions(USE_FALLBACK_HASH)
endif()