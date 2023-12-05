#pragma once

#include "tls-utils/type.h"
#include "tls-context/context.h"

#include <string>
#include <list>
#include <functional>

namespace leaf::network::tls {

	/**
	 * Generates TLSPlainText
	 * Structure:
	 * 	content_type type
	 * 	protocol_version_t legacy_record_version
	 * 	uint16 length
	 * 	opaque fragment[TLSPlaintext.length]
	 */
	class record {

		virtual std::string build_content_() = 0;

		virtual void print(std::ostream&) const = 0;

	public:
		enum class content_type_t: uint8_t {
			invalid = 0, change_cipher_spec = 20, alert = 21, handshake = 22, application_data = 23
		};

		const bool encrypted;

		content_type_t type;

		protocol_version_t legacy_record_version = protocol_version_t::TLS1_2;

		record(content_type_t type, bool encrypted);

		std::list<std::string> build(context&);

		/**
		 * `parse()` only parse the incoming records, thus does not care about state of the `context`.
		 */
		static void parse(context& context, const std::function<void(record&)>& callback);

		friend std::ostream& operator<<(std::ostream&, const record&);

		virtual ~record() = default;
	};

	class application_data: public record {
		std::string build_content_() override;

		void print(std::ostream& ostream) const override;

	public:
		std::string data;

		application_data(std::string_view data);
	};
}
