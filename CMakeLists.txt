cmake_minimum_required(VERSION 3.24)
project(ExplainBin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(EXPLAINBIN_BUILD_UI "Build the Qt 6 graphical interface" ON)
option(EXPLAINBIN_BUILD_CLI "Build the command-line analyzer" ON)
option(EXPLAINBIN_BUILD_TESTS "Build the GoogleTest test suite" ON)
option(EXPLAINBIN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

if(NOT WIN32)
    message(FATAL_ERROR "ExplainBin analyzes Windows PE files and currently targets Windows only.")
endif()

enable_language(RC)
configure_file(
    resources/version.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.rc
    @ONLY
)
set(EXPLAINBIN_VERSION_RESOURCE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

include(FetchContent)
include(GNUInstallDirs)

find_package(nlohmann_json 3.11.3 QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

set(EXPLAINBIN_CORE_SOURCES
    src/core/Analyzer.cpp
    src/core/EntropyAnalyzer.cpp
    src/core/FileReader.cpp
    src/core/FindingsEngine.cpp
    src/core/HashCalculator.cpp
    src/core/ImportAnalyzer.cpp
    src/core/PEParser.cpp
    src/core/PEFormat.cpp
    src/core/SignatureVerifier.cpp
    src/core/Types.cpp
    src/core/Util.cpp
)

add_library(explainbin_core STATIC ${EXPLAINBIN_CORE_SOURCES})
add_library(ExplainBin::Core ALIAS explainbin_core)
target_include_directories(explainbin_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_definitions(explainbin_core
    PUBLIC
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
        EXPLAINBIN_VERSION_STRING="${PROJECT_VERSION}"
)

target_link_libraries(explainbin_core
    PUBLIC
        bcrypt
        crypt32
        wintrust
)

add_library(explainbin_reports STATIC
    src/reports/HTMLExporter.cpp
    src/reports/JSONExporter.cpp
    src/reports/ReportUtil.cpp
    src/reports/TextExporter.cpp
)
add_library(ExplainBin::Reports ALIAS explainbin_reports)
target_link_libraries(explainbin_reports
    PUBLIC explainbin_core
    PRIVATE nlohmann_json::nlohmann_json
)

function(explainbin_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
        if(EXPLAINBIN_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor
        )
        if(EXPLAINBIN_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

explainbin_set_warnings(explainbin_core)
explainbin_set_warnings(explainbin_reports)

if(EXPLAINBIN_BUILD_CLI)
    add_executable(explainbin-cli src/cli/main.cpp ${EXPLAINBIN_VERSION_RESOURCE})
    target_link_libraries(explainbin-cli PRIVATE explainbin_reports)
    explainbin_set_warnings(explainbin-cli)
    if(MINGW)
        target_link_options(explainbin-cli PRIVATE -municode)
    endif()
endif()

if(EXPLAINBIN_BUILD_UI)
    find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Svg Concurrent)
    qt_standard_project_setup(REQUIRES 6.5)

    qt_add_executable(explainbin WIN32
        src/main.cpp
        src/ui/MainWindow.cpp
        src/ui/Dashboard.cpp
        src/ui/FileAnalysisView.cpp
        src/ui/PEStructureView.cpp
        src/ui/ImportsExportsView.cpp
        src/ui/SignatureView.cpp
        src/ui/FindingsView.cpp
        src/ui/ReportView.cpp
        src/ui/SettingsView.cpp
        src/ui/Theme.cpp
        src/ui/widgets/Card.cpp
        src/ui/widgets/SeverityBadge.cpp
        src/ui/widgets/SeverityChart.cpp
        include/explainbin/ui/MainWindow.hpp
        include/explainbin/ui/Dashboard.hpp
        include/explainbin/ui/FileAnalysisView.hpp
        include/explainbin/ui/PEStructureView.hpp
        include/explainbin/ui/ImportsExportsView.hpp
        include/explainbin/ui/SignatureView.hpp
        include/explainbin/ui/FindingsView.hpp
        include/explainbin/ui/ReportView.hpp
        include/explainbin/ui/SettingsView.hpp
        include/explainbin/ui/widgets/Card.hpp
        include/explainbin/ui/widgets/SeverityBadge.hpp
        include/explainbin/ui/widgets/SeverityChart.hpp
        resources/resources.qrc
        ${EXPLAINBIN_VERSION_RESOURCE}
    )
    target_link_libraries(explainbin PRIVATE explainbin_reports Qt6::Widgets Qt6::Svg Qt6::Concurrent)
    set_target_properties(explainbin PROPERTIES
        WIN32_EXECUTABLE TRUE
        OUTPUT_NAME "ExplainBin"
    )
    explainbin_set_warnings(explainbin)
endif()

if(EXPLAINBIN_BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()
    add_subdirectory(tests)
endif()

install(TARGETS explainbin_core explainbin_reports
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
if(EXPLAINBIN_BUILD_CLI)
    install(TARGETS explainbin-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(EXPLAINBIN_BUILD_UI)
    install(TARGETS explainbin RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
