include(GoogleTest)

add_executable(explainbin_tests
    AnalyzerTests.cpp
    EntropyTests.cpp
    FindingsTests.cpp
    HashCalculatorTests.cpp
    PEParserTests.cpp
    ReportTests.cpp
    SignatureTests.cpp
)

target_include_directories(explainbin_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(explainbin_tests
    PRIVATE
        explainbin_reports
        nlohmann_json::nlohmann_json
        GTest::gtest_main
)

if(MSVC)
    target_compile_options(explainbin_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
else()
    target_compile_options(explainbin_tests PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()

gtest_discover_tests(explainbin_tests
    DISCOVERY_TIMEOUT 60
    PROPERTIES TIMEOUT 120
)

if(TARGET explainbin-cli)
    add_test(NAME Cli.Version COMMAND explainbin-cli --version)
    set_tests_properties(Cli.Version PROPERTIES
        PASS_REGULAR_EXPRESSION "ExplainBin ${PROJECT_VERSION}"
    )

    add_test(NAME Cli.Help COMMAND explainbin-cli --help)
    set_tests_properties(Cli.Help PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage:"
    )

    add_test(NAME Cli.RejectsUnknownOption COMMAND explainbin-cli --not-a-real-option)
    set_tests_properties(Cli.RejectsUnknownOption PROPERTIES WILL_FAIL TRUE)
endif()
