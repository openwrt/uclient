cmake_minimum_required(VERSION 3.10)

INCLUDE(CheckIncludeFiles)

PROJECT(uclient C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
        ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
        ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Wno-unused-parameter -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

FIND_PATH(ubox_include_dir libubox/ustream-ssl.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})
OPTION(BUILD_UCODE "build ucode plugin" ON)

IF(BUILD_STATIC)
  FIND_LIBRARY(ubox_library NAMES ubox.a)
ELSE(BUILD_STATIC)
  FIND_LIBRARY(ubox_library NAMES ubox)
ENDIF(BUILD_STATIC)

IF(APPLE)
  SET(UCODE_MODULE_LINK_OPTIONS "LINKER:-undefined,dynamic_lookup")
ENDIF()

SET(LIB_SOURCES uclient.c uclient-http.c uclient-utils.c)
ADD_LIBRARY(uclient SHARED ${LIB_SOURCES})
TARGET_LINK_LIBRARIES(uclient ${ubox_library} dl)

SET(CLI_SOURCES uclient-fetch.c progress.c)
ADD_EXECUTABLE(uclient-fetch ${CLI_SOURCES})
TARGET_LINK_LIBRARIES(uclient-fetch uclient)

IF(UNIT_TESTING)
  ADD_DEFINITIONS(-DUNIT_TESTING)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(tests)

  IF(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    ADD_LIBRARY(uclient-san SHARED ${LIB_SOURCES})
    TARGET_COMPILE_OPTIONS(uclient-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
    TARGET_LINK_OPTIONS(uclient-san PRIVATE -fsanitize=undefined,address,leak)
    TARGET_LINK_LIBRARIES(uclient-san ${ubox_library} dl)

    ADD_EXECUTABLE(uclient-fetch-san ${CLI_SOURCES})
    TARGET_COMPILE_OPTIONS(uclient-fetch-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
    TARGET_LINK_OPTIONS(uclient-fetch-san PRIVATE -fsanitize=undefined,address,leak)
    TARGET_LINK_LIBRARIES(uclient-fetch-san uclient-san ${ubox_library} dl)
  ENDIF()
ENDIF()

IF(BUILD_UCODE)
  ADD_LIBRARY(uclient_lib MODULE ucode.c)
  SET_TARGET_PROPERTIES(uclient_lib PROPERTIES OUTPUT_NAME uclient PREFIX "")
  TARGET_LINK_OPTIONS(uclient_lib PRIVATE ${UCODE_MODULE_LINK_OPTIONS})
  TARGET_LINK_LIBRARIES(uclient_lib uclient)
  INSTALL(TARGETS uclient_lib
	LIBRARY DESTINATION lib/ucode
  )
ENDIF()

INSTALL(FILES uclient.h uclient-utils.h
	DESTINATION include/libubox
)
INSTALL(TARGETS uclient uclient-fetch
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)

