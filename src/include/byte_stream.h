#pragma once
#include <string>
#include <cstdint>

namespace leaf {

	struct istream {

		virtual std::uint8_t read() = 0;

		virtual std::string read(std::size_t count) {
			std::string str;
			str.reserve(count);
			for (std::size_t i = 0; i < count; ++i)
				str.push_back(read());
			return str;
		}

		virtual std::string read_until(std::string_view delim) {
			std::string str;
			while (true) {
				auto ch = read();
				str.push_back(ch);
				if (delim.contains(ch))
					break;
			}
			return str;
		}

		virtual void skip(const std::size_t count) {
			read(count);
		}
	};


	struct ostream {

		virtual void write(std::uint8_t octet) = 0;

		virtual void write(std::string_view data) {
			for (auto c: data)
				write(c);
		}
	};


	struct stream: virtual istream, virtual ostream {
	};


	struct string_stream: stream, std::string {

		using std::string::operator=;

		std::uint8_t read() override {
			const auto c = front();
			erase(0, 1);
			return c;
		}

		std::string read(std::size_t count) override {
			const auto str = substr(0, count);
			erase(0, count);
			return str;
		}

		std::string read_until(std::string_view delim) override {
			const auto pos = find_first_of(delim);
			const auto str = substr(0, pos);
			erase(0, pos);
			return str;
		}

		void write(std::uint8_t octet) override {
			push_back(octet);
		}

		void write(std::string_view data) override {
			append(data);
		}
	};
}
