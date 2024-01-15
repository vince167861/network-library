#pragma once

#include "tls-utils/type.h"
#include "tls-context/context.h"
#include "tls-utils/binary_object.h"

#include <string>
#include <format>

namespace leaf::network::tls {

	/**
	 * \brief A protocol layer message.
	 */
	struct message: binary_object {
		virtual void format(std::format_context::iterator&) const = 0;
	};


	/**
	 * \brief A record layer packet.
	 */
	struct record final: binary_object {

		content_type_t type;

		bool encrypted;

		protocol_version_t legacy_record_version = protocol_version_t::TLS1_2;

		std::string messages;

		std::string to_bytestring() const override;

		static record extract(context&);

		static record
		construct(content_type_t, bool encrypted, const message&, context&);

		record(content_type_t type, bool encrypted, context&);

		context& context_;
	};
}


template<>
struct std::formatter<leaf::network::tls::record> {

	constexpr auto parse(const std::format_parse_context& ctx) {
		return ctx.begin();
	}

	std::format_context::iterator format(const leaf::network::tls::record&, std::format_context&) const;
};
