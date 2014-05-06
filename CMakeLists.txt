cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckIncludeFiles)

PROJECT(uclient C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_LIBRARY(uclient SHARED uclient.c uclient-http.c uclient-utils.c)
TARGET_LINK_LIBRARIES(uclient ubox dl)

ADD_EXECUTABLE(uclient-fetch uclient-fetch.c)
TARGET_LINK_LIBRARIES(uclient-fetch uclient)

INSTALL(FILES uclient.h uclient-utils.h
	DESTINATION include/libubox
)
INSTALL(TARGETS uclient uclient-fetch
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
