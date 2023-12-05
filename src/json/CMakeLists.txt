add_library(json json.cpp)
target_sources(json PUBLIC FILE_SET json_headers TYPE HEADERS BASE_DIRS include FILES
		include/json/json.h)
install(TARGETS json EXPORT leaf
		FILE_SET json_headers
		LIBRARY)
