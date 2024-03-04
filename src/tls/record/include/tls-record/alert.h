#pragma once
#include "record.h"
#include "tls/util/type.h"

namespace network::tls {

	struct alert final: message, std::runtime_error {

		alert_level_t level;

		alert_description_t description;

		alert(alert_level_t, alert_description_t, std::string_view);

		alert(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;

		static alert close_notify();

		static alert unexpected_message(std::string_view = "unexpected message");

		static alert bad_record_mac(std::string_view = "bad record mac");

		static alert record_overflow(std::string_view = "record overflow");

		static alert handshake_failure(std::string_view = "handshake failure");

		static alert decode_error(std::string_view = "decode error");

		static alert illegal_parameter(std::string_view = "illegal parameter");

		static alert decrypt_error(std::string_view = "decrypt error");
	};

}
