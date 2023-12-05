#include "tls-record/alert.h"
#include "utils.h"

#include <sstream>
#include <utility>

namespace leaf::network::tls {

	alert::alert(alert_level_t lvl, alert_description_t d, std::string debug, bool encrypted)
			: record(content_type_t::alert, encrypted), debug_string(std::move(debug)), level(lvl), description(d) {
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

	const char* alert::what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW {
		return debug_string.c_str();
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

	std::string alert::build_content_() {
		std::string msg;
		reverse_write(msg, level);
		reverse_write(msg, description);
		return msg;
	}

	void alert::print(std::ostream& s) const {
		s << "Alert\n\tLevel: " << level << "\n\tDescription: " << description << '\n';
		if (!debug_string.empty())
			s << "\tDebug: " << debug_string << '\n';
	}

	alert::alert(std::string_view source, bool encrypted)
			: record(content_type_t::alert, encrypted) {
		auto ptr = source.begin();
		reverse_read(ptr, level);
		reverse_read(ptr, description);
	}

	alert alert::close_notify(bool encrypted) {
		return {alert_level_t::warning, alert_description_t::close_notify, "", encrypted};
	}
}
