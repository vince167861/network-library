#include "tls-record/alert.h"
#include "utils.h"

#include <utility>

namespace leaf::network::tls {

	std::format_context::iterator alert::format(std::format_context::iterator it) const {
		it = std::format_to(it, "Alert\n\tLevel: {}\n\tDescription: {}", level, description);
		if (!debug_string.empty())
			it = std::format_to(it, "\n\tDebug: {}", debug_string);
		return it;
	}

	alert::operator byte_string() const {
		byte_string str;
		write(std::endian::big, str, level);
		write(std::endian::big, str, description);
		return str;
	}

	const char* alert::what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW {
		return debug_string.c_str();
	}

	alert::alert(const alert_level_t level, const alert_description_t dsc, std::string debug)
		: level(level), description(dsc), debug_string(std::move(debug)) {
	}

	alert::alert(const byte_string_view source) {
		auto it = source.begin();
		read(std::endian::big, level, it);
		read(std::endian::big, description, it);
	}

	alert alert::bad_record_mac() {
		return {alert_level_t::fatal, alert_description_t::bad_record_mac};
	}

	alert alert::unexpected_message() {
		return {alert_level_t::fatal, alert_description_t::unexpected_message};
	}

	alert alert::record_overflow() {
		return {alert_level_t::fatal, alert_description_t::record_overflow};
	}

	alert alert::handshake_failure() {
		return {alert_level_t::fatal, alert_description_t::handshake_failure};
	}

	alert alert::decode_error(const std::string& debug_description) {
		return {alert_level_t::fatal, alert_description_t::decode_error, "Decode error: " + debug_description};
	}

	alert alert::decode_error_early_end_of_data(
			std::string_view field_name, std::size_t actual_size, std::size_t expected_size) {
		return decode_error(
				std::format("{} expect {}, but only {} left (early end of message)",
							field_name, expected_size, actual_size));
	}

	alert alert::illegal_parameter() {
		return {alert_level_t::fatal, alert_description_t::illegal_parameter};
	}

	alert alert::decrypt_error() {
		return {alert_level_t::fatal, alert_description_t::decrypt_error};
	}

	alert alert::close_notify() {
		return {alert_level_t::warning, alert_description_t::close_notify, ""};
	}
}
