# LinkHelm-exp — experimental transparent data plane (WinDivert + SOCKS5).
#
# beta0.2.0: rebuilt ON TOP OF the LinkHelm v1.1.3 C++ desktop app
# (backup_v1.1.3/): 1.1.3 UI (beautified, reconnect governor) kept verbatim,
#   removed: accel_controller, subscription, relay, tun_manager (Wintun+lwIP)
#   added:   exp_socks5 (RFC 1928/1929 client), exp_engine (WinDivert
#            capture + TCP reflection + UDP ASSOCIATE pool + half-routes)
#   kept:    connect page, ICS sharing, file transfer assistant, tray
#
# WinDivert is loaded dynamically at runtime — WinDivert.dll and
# WinDivert64.sys must sit next to the built exe (see windivert/).
#
#   cmake -S . -B build -G "MinGW Makefiles" ^
#         -DCMAKE_CXX_COMPILER=../toolchain/mingw64/bin/g++.exe
#   cmake --build build --parallel
cmake_minimum_required(VERSION 3.16)
project(LinkHelmExp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/../toolchain/mingw64/bin/g++.exe")
endif()

add_executable(LinkHelmExp WIN32
    src/app_main.cpp
    src/net_control.cpp
    src/tray.cpp
    src/file_transfer.cpp
    src/ft_receiver.cpp
    src/exp_socks5.cpp
    src/exp_engine.cpp
)

target_include_directories(LinkHelmExp PRIVATE src windivert)
target_compile_definitions(LinkHelmExp PRIVATE
    UNICODE _UNICODE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX)

# Same size/stability pass as the mainline beta1.0.8 build: no RTTI, no C++
# exceptions (the engine never throws — failures return codes), -Os,
# stripped, section GC, static libstdc++/libgcc/winpthread.
target_compile_options(LinkHelmExp PRIVATE
    -fno-rtti -fno-exceptions -Os -ffunction-sections -fdata-sections)

target_link_libraries(LinkHelmExp PRIVATE
    winhttp iphlpapi shlwapi advapi32 comctl32 shell32 user32 gdi32 ws2_32
    wsock32 ole32 oleaut32 comdlg32)

set_target_properties(LinkHelmExp PROPERTIES
    LINK_FLAGS "-municode -mwindows -static -static-libgcc -static-libstdc++ -s -Wl,--gc-sections")
