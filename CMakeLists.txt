cmake_minimum_required(VERSION 3.20)
project(SelectiveTunnel VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ST_CORE_SOURCES
    src/core/utf.cpp
    src/core/util.cpp
    src/core/sha256.cpp
    src/core/json_io.cpp
    src/core/paths.cpp
    src/core/crypto.cpp
    src/core/profile.cpp
    src/core/policy.cpp
    src/core/engine_config.cpp
    src/core/engine.cpp
    src/core/status.cpp
    src/core/control.cpp
    src/core/ipc.cpp
    src/core/guards.cpp
    src/core/proxy_bypass.cpp
    src/core/proxy_bypass_winhttp.cpp
    src/core/win_service.cpp
)

add_library(st_core STATIC ${ST_CORE_SOURCES})
target_include_directories(st_core PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/third_party)
target_compile_definitions(st_core PUBLIC UNICODE _UNICODE)

if(MSVC)
    target_compile_options(st_core PUBLIC /utf-8 /W3 /EHsc)
endif()

if(WIN32)
    target_compile_definitions(st_core PUBLIC _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(st_core PUBLIC
        crypt32 bcrypt advapi32 ole32 oleaut32 uuid shell32 shlwapi
        ws2_32 iphlpapi comctl32 comdlg32 winhttp wininet wtsapi32 dnsapi taskschd
    )
endif()

set(ST_APP_SOURCES
    src/app/main.cpp
    src/app/gui.cpp
    src/app/settings.cpp
    src/app/install.cpp
    src/app/diagnose.cpp
    src/app/selftest.cpp
)

if(WIN32)
    add_executable(SelectiveTunnel WIN32 ${ST_APP_SOURCES} src/app/app.rc)
    target_link_libraries(SelectiveTunnel PRIVATE st_core)
    target_include_directories(SelectiveTunnel PRIVATE ${CMAKE_SOURCE_DIR}/src)

    add_executable(SelectiveTunnelSvc src/service/main.cpp src/service/supervisor.cpp)
    target_link_libraries(SelectiveTunnelSvc PRIVATE st_core)
    target_include_directories(SelectiveTunnelSvc PRIVATE ${CMAKE_SOURCE_DIR}/src)
    if(MINGW)
        target_link_options(SelectiveTunnel PRIVATE -static -municode)
        target_link_options(SelectiveTunnelSvc PRIVATE -static)
        target_compile_options(st_core PUBLIC -finput-charset=UTF-8)
    endif()
    add_custom_command(TARGET SelectiveTunnel POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/policy $<TARGET_FILE_DIR:SelectiveTunnel>/policy
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:SelectiveTunnelSvc> $<TARGET_FILE_DIR:SelectiveTunnel>/SelectiveTunnelSvc.exe
    )
else()
    add_executable(st_selftest ${ST_APP_SOURCES})
    target_link_libraries(st_selftest PRIVATE st_core)
    target_include_directories(st_selftest PRIVATE ${CMAKE_SOURCE_DIR}/src)
endif()
