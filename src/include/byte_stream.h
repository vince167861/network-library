#pragma once
#include "common.h"
#include <algorithm>

namespace leaf {

	struct istream {

		virtual std::uint8_t read() = 0;

		virtual byte_string read(const std::size_t count) {
			byte_string str;
			str.reserve(count);
			for (std::size_t i = 0; i < count; ++i)
				str.push_back(read());
			return str;
		}

		virtual std::string read_line() {
			std::string str;
			for (;;) {
				const auto _c = read();
				str.push_back(_c);
				if (std::ranges::contains("\r\n", _c))
					break;
			}
			return str;
		}

		virtual void skip(const std::size_t count) {
			read(count);
		}

		virtual ~istream() = default;
	};


	struct ostream {

		virtual void write(std::uint8_t octet) = 0;

		virtual void write(const byte_string_view data) {
			for (auto c: data)
				write(c);
		}

		virtual ~ostream() = default;
	};


	struct stream: virtual istream, virtual ostream {
	};


	struct string_stream: stream, byte_string {

		using byte_string::byte_string, byte_string::operator=;

		std::uint8_t read() override {
			if (empty())
				throw std::runtime_error("empty buffer");
			const auto c = front();
			erase(0, 1);
			return c;
		}

		byte_string read(std::size_t count) override {
			const auto str = substr(0, count);
			erase(0, count);
			return str;
		}

		void write(std::uint8_t octet) override {
			push_back(octet);
		}

		void write(const byte_string_view data) override {
			append(data);
		}
	};
}
