#pragma once

#include "tls-utils/type.h"
#include "binary_object.h"
#include "basic_endpoint.h"
#include "tls-utils/type.h"
#include "tls-cipher/traffic_secret_manager.h"

#include <string>
#include <format>

namespace leaf::network::tls {

	/**
	 * \brief A protocol layer message.
	 */
	struct message: binary_object {

		virtual std::format_context::iterator format(std::format_context::iterator) const = 0;
	};


	/**
	 * \brief A record layer packet.
	 */
	struct record final: binary_object {

		using opt_cipher = std::optional<std::reference_wrapper<traffic_secret_manager>>;

		content_type_t type;

		protocol_version_t legacy_record_version = protocol_version_t::TLS1_2;

		std::string messages;

		record(content_type_t type, opt_cipher);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		static record extract(endpoint&, traffic_secret_manager&);

		static record construct(content_type_t, opt_cipher, const message&);

		bool encrypted() const {
			return cipher_.has_value();
		}

	private:
		opt_cipher cipher_;
	};
}


template<>
struct std::formatter<leaf::network::tls::message> {

	constexpr auto parse(const std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::network::tls::message& msg, std::format_context& ctx) const {
		return msg.format(ctx.out());
	}
};


template<>
struct std::formatter<leaf::network::tls::record> {

	constexpr auto parse(const std::format_parse_context& ctx) {
		return ctx.begin();
	}

	std::format_context::iterator format(const leaf::network::tls::record&, std::format_context&) const;
};
