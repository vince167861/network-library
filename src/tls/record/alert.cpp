#include "tls-record/alert.h"
#include "utils.h"

#include <sstream>
#include <utility>

namespace leaf::network::tls {

	void alert::format(std::format_context::iterator& it) const {
		it = std::format_to(it, "Alert\n\tLevel: {}\n\tDescription: {}", level, description);
		if (!debug_string.empty())
			it = std::format_to(it, "\n\tDebug: {}", debug_string);
	}

	std::string alert::to_bytestring() const {
		std::string str;
		reverse_write(str, level);
		reverse_write(str, description);
		return str;
	}

	const char* alert::what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW {
		return debug_string.c_str();
	}

	alert::alert(const alert_level_t level, const alert_description_t dsc, std::string debug)
		: level(level), description(dsc), debug_string(std::move(debug)) {
	}

	alert::alert(const std::string_view source) {
		auto ptr = source.begin();
		reverse_read(ptr, level);
		reverse_read(ptr, description);
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
		std::stringstream msg;
		msg << field_name << " expect " << expected_size << ", but only " << actual_size << " left (early end of message)";
		return decode_error(msg.str());
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
