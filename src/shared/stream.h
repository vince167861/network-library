#pragma once
#include <string>

namespace leaf {

	class stream {
	public:
		virtual std::string read(std::size_t count) = 0;

		virtual void skip(const std::size_t count) {
			read(count);
		}

		virtual std::string read_until(std::string_view terminator) {
			std::string str;
			while (true) {
				auto ch = read(1);
				if (!ch.empty())
					str += ch;
				if (terminator.contains(ch[0]))
					break;
			}
			return str;
		}

		virtual std::size_t write(std::string_view) = 0;

		virtual ~stream() = default;
	};

}
