cmake_minimum_required(VERSION 3.14)
project(LigamentCredentialProvider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE -D_WINDLL)

# Исходники сохранены в UTF-8 (русские L"..."-литералы интерфейса тайла).
# Без /utf-8 MSVC декодирует литералы по системной кодовой странице машины,
# где идёт сборка (на en-US CI-раннере это CP1252): кириллица «запекается»
# в DLL кракозябрами ровно того вида, что виден на тайле входа. Флаг задаёт
# и source-, и execution-charset = UTF-8 независимо от локали сборщика.
if(MSVC)
    add_compile_options(/utf-8)
endif()

set(SOURCES
    dllmain.cpp
    ClassFactory.cpp
    LigamentProvider.cpp
    LigamentCredential.cpp
    HttpApiClient.cpp
    WebAuthnClient.cpp
    exports.def
)

set(HEADERS
    common.h
    guid.h
    ClassFactory.h
    LigamentProvider.h
    LigamentCredential.h
    HttpApiClient.h
    WebAuthnClient.h
)

add_library(LigamentCredentialProvider SHARED ${SOURCES} ${HEADERS})

target_link_libraries(LigamentCredentialProvider PRIVATE
    winhttp
    secur32
    credui
    shlwapi
    wtsapi32
    ole32
    user32
    advapi32
)

set_target_properties(LigamentCredentialProvider PROPERTIES
    OUTPUT_NAME "LigamentCredentialProvider"
    LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/exports.def\""
)
