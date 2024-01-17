#pragma once

#include "stream.h"

#include <string>
#include <cstdint>

namespace leaf::network {

	class client: public stream {
	public:
		virtual bool connect(std::string_view host, uint16_t port) = 0;

		virtual bool connected() const = 0;

		virtual bool finish() = 0;

		virtual std::size_t available() = 0;

		virtual void close() = 0;

		/**
		 * \brief Read until reaches `terminator`.
		 * \return Read string with `terminator` at the end if no error occur.
		 */
		std::string read_until(std::string_view terminator) override {
			std::string str;
			while (connected()) {
				auto ch = read(1);
				if (!ch.empty())
					str += ch;
				if (terminator.contains(ch[0]))
					break;
			}
			return str;
		}

		/**
		 * \brief Read until connection closed
		 */
		virtual std::string read_all() {
			std::string str;
			while (connected()) {
				try {
					str += read(50);
				} catch (const std::exception&) {
					break;
				}
			}
			return str;
		}
	};
}
