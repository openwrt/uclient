cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckIncludeFiles)

PROJECT(uclient C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

FIND_PATH(ubox_include_dir libubox/ustream-ssl.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

IF(BUILD_STATIC)
  FIND_LIBRARY(ubox_library NAMES ubox.a)
ELSE(BUILD_STATIC)
  FIND_LIBRARY(ubox_library NAMES ubox)
ENDIF(BUILD_STATIC)

ADD_LIBRARY(uclient SHARED uclient.c uclient-http.c uclient-utils.c)
TARGET_LINK_LIBRARIES(uclient ${ubox_library} dl)

ADD_EXECUTABLE(uclient-fetch uclient-fetch.c progress.c)
TARGET_LINK_LIBRARIES(uclient-fetch uclient)

INSTALL(FILES uclient.h uclient-utils.h
	DESTINATION include/libubox
)
INSTALL(TARGETS uclient uclient-fetch
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
