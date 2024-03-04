#pragma once
#include "basic_stream.h"
#include "tls/util/type.h"
#include "tls/cipher/traffic_secret_manager.h"
#include <string>
#include <format>

namespace network::tls {

	/**
	 * \brief A protocol layer message.
	 */
	struct message {

		virtual std::format_context::iterator format(std::format_context::iterator) const = 0;

		virtual operator byte_string() const = 0;

		virtual ~message() = default;
	};


	/**
	 * \brief A record layer packet.
	 */
	struct record final {

		using opt_cipher = std::optional<std::reference_wrapper<traffic_secret_manager>>;

		content_type_t type;

		protocol_version_t version = protocol_version_t::TLS1_2;

		byte_string messages;

		record(content_type_t type, opt_cipher);

		operator byte_string() const;

		static record extract(istream&, traffic_secret_manager& cipher);

		static record construct(content_type_t, opt_cipher, const message&);

		bool encrypted() const {
			return cipher_.has_value();
		}

	private:
		opt_cipher cipher_;
	};
}


template<>
struct std::formatter<network::tls::message> {

	constexpr auto parse(const std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const network::tls::message& msg, std::format_context& ctx) const {
		return msg.format(ctx.out());
	}
};


template<>
struct std::formatter<network::tls::record> {

	constexpr auto parse(const std::format_parse_context& ctx) {
		return ctx.begin();
	}

	std::format_context::iterator format(const network::tls::record& record, format_context& ctx) const {
		return std::format_to(ctx.out(), "record [{}, payload size = {}]", record.type, record.messages.size());
	}
};
