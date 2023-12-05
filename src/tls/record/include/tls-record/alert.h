#pragma once

#include "record.h"
#include "tls-utils/type.h"

#include <exception>

namespace leaf::network::tls {

	class alert: public record, public std::exception {
		std::string debug_string, out;

		std::string build_content_() override;

		void print(std::ostream& ostream) const override;

	public:
		alert_level_t level;

		alert_description_t description;

		alert(alert_level_t, alert_description_t, std::string debug = "", bool encrypted = false);

		alert(std::string_view, bool encrypted);

		const char* what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;

		static alert close_notify(bool encrypted);

		static alert unexpected_message();

		static alert bad_record_mac();

		static alert record_overflow();

		static alert handshake_failure();

		static alert illegal_parameter();

		static alert decode_error(const std::string& debug_description);

		static alert decode_error_early_end_of_data(std::string_view field_name, std::size_t actual_size, std::size_t expected_size);

		static alert decrypt_error();
	};

}
