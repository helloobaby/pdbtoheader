cmake_minimum_required (VERSION 3.11) # fetchcontent after 3.11 
project(pdbtoheader)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/idasdk76/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/idasdk76/lib/x64_win_vc_64/) #链接器->常规->附加库目录

link_libraries(ida.lib)#链接器->输入

add_subdirectory(src)  ## 增加一个叫src的子目录(连着一起cmake)
add_subdirectory(dependencies)

message(${IDA_INSTALL_DIR}) # cmake -DIDA_INSTALL_DIR="E:\IDA Pro 7.6" ..