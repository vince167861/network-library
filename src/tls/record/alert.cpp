#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	std::format_context::iterator alert::format(std::format_context::iterator it) const {
		return std::format_to(it, "Alert\n\tlevel: {}\n\tdescription: {}\n\tdebug: {}", level, description, what());
	}

	alert::operator byte_string() const {
		byte_string str;
		write(std::endian::big, str, level);
		write(std::endian::big, str, description);
		return str;
	}

	alert::alert(const alert_level_t level, const alert_description_t dsc, const std::string_view __d)
		: std::runtime_error(std::string(__d)), level(level), description(dsc) {
	}

	alert::alert(const byte_string_view source)
		: std::runtime_error("(parsed)"){
		auto it = source.begin();
		read(std::endian::big, level, it);
		read(std::endian::big, description, it);
	}

	alert alert::unexpected_message(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::unexpected_message, __d};
	}

	alert alert::bad_record_mac(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::bad_record_mac, __d};
	}

	alert alert::record_overflow(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::record_overflow, __d};
	}

	alert alert::handshake_failure(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::handshake_failure, __d};
	}

	alert alert::decode_error(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::decode_error, __d};
	}

	alert alert::illegal_parameter(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::illegal_parameter, __d};
	}

	alert alert::decrypt_error(const std::string_view __d) {
		return {alert_level_t::fatal, alert_description_t::decrypt_error, __d};
	}

	alert alert::close_notify() {
		return {alert_level_t::warning, alert_description_t::close_notify, ""};
	}
}
