cmake_minimum_required(VERSION 3.19)

if("${NPCAP_SDK_PATH}" STREQUAL "")
	message(FATAL_ERROR "Npcap path not defined")
endif()

project(WakeOnLanForwarder)

add_executable(${PROJECT_NAME} src/main.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC ${NPCAP_SDK_PATH}/Include)

target_link_libraries(${PROJECT_NAME} ${NPCAP_SDK_PATH}/Lib/x64/wpcap.lib 
				${NPCAP_SDK_PATH}/Lib/x64/Packet.lib)

set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/DELAYLOAD:wpcap.dll")