add_library(number
		number_base.cpp
		var_number.cpp
		big_number.cpp)
target_include_directories(number
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(number
		PUBLIC FILE_SET number_headers TYPE HEADERS BASE_DIRS include FILES
		include/number/number_base.h
		include/number/flexible.h)
install(TARGETS number EXPORT leaf
		FILE_SET number_headers
		LIBRARY)
