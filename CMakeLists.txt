cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
project      (netprobe)

set  (CMAKE_AUTORCC ON)
set  (project_SOURCES main.cpp netpcap.cpp)
set  (project_HEADERS netpcap.h)
set  (project_FORMS   )
set  (project_RESOURCES )
#set  (CMAKE_CXX_FLAGS -g)
set(CMAKE_CXX_STANDARD 11)
find_package(libpcap)
#find_package(Qt5Widgets)

#QT5_WRAP_CPP (project_HEADERS_MOC   ${project_HEADERS})
#QT5_WRAP_UI  (project_FORMS_HEADERS ${project_FORMS})
#QT5_ADD_RESOURCES(project_RESOURCES_RCC ${project_RESOURCES})

#ADD_DEFINITIONS (${QT_DEFINITIONS})


ADD_EXECUTABLE  (netprobe    ${project_SOURCES}
                             ${project_FORMS_HEADERS}
                             ${project_RESOURCES} 
			     ${project_HEADERS_MOC})

#qt5_use_modules (netprobe Widgets)
set(CMAKE_EXE_LINKER_FLAGS "-lpcap")  
  
TARGET_LINK_LIBRARIES(netprobe ${CMAKE_EXE_LINKER_FLAGS}) 
