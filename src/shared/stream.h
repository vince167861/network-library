#pragma once
#include <string>

namespace leaf {

	class stream {
	public:
		virtual std::string read(std::size_t count) = 0;

		virtual std::size_t write(std::string_view) = 0;

		virtual ~stream() = default;
	};

}
