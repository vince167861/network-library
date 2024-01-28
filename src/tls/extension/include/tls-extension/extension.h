#pragma once

#include "binary_object.h"
#include "tls-utils/type.h"
#include "tls-context/context.h"

#include <list>
#include <string>

namespace leaf::network::tls {


	struct raw_extension final: binary_object {

		ext_type_t type;

		std::string data;

		raw_extension(ext_type_t, std::string);

		std::string to_bytestring(std::endian = std::endian::big) const override;
	};


	/**
	 * base class of TLS handshake messages
	 */
	struct extension_base: binary_object {

		virtual void format(std::format_context::iterator&, std::size_t level) const = 0;

		virtual operator raw_extension() const = 0;

		std::string to_bytestring(std::endian = std::endian::big) const final;
	};


	/**
	 * TLS supported_version extension
	 */
	struct supported_versions final: extension_base {

		enum class msg_type_t {
			client_hello,
			server_hello
		} message_type;

		std::list<protocol_version_t> versions;

		/**
		 * \brief Creates a supported_versions extension under |context|.
		 */
		explicit supported_versions(const context& context);

		supported_versions(std::string_view, context& context);

		void format(std::format_context::iterator& it, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * TLS key_share extension
	 */
	struct key_share final: extension_base {

		std::list<std::pair<named_group_t, std::string>> shares;

		enum class msg_type_t {
			client_hello,
			hello_retry_request,
			server_hello
		} message_type;

		explicit key_share(const context& context);

		key_share(std::string_view, bool is_hello_retry_request, context&);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * TLS supported_groups extension.
	 */
	struct supported_groups final: extension_base {

		enum class msg_type_t {
			client_hello,
			server_hello
		} message_type;

		std::list<named_group_t> named_group_list;

		explicit supported_groups(const context&);

		supported_groups(std::string_view, context&);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * TLS signature_algorithms extension
	 */
	struct signature_algorithms final: extension_base {

		std::list<signature_scheme_t> list;

		signature_algorithms(std::initializer_list<signature_scheme_t>);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * TLS psk_key_exchange_modes extension
	 */
	struct psk_key_exchange_modes final: extension_base {

		std::list<psk_key_exchange_mode_t> modes;

		psk_key_exchange_modes(std::initializer_list<psk_key_exchange_mode_t>);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * TLS server_name extension
	 */
	struct server_name final: extension_base {

		enum class name_type_t: uint8_t {
			host_name = 0
		};

		std::list<std::pair<name_type_t, std::string>> server_name_list;

		server_name(std::initializer_list<std::pair<name_type_t, std::string>>);

		server_name(std::string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * \brief TLS renegotiation_info extension
	 */
	struct renegotiation_info final: extension_base {

		std::string renegotiated_connection;

		explicit renegotiation_info(std::string_view verify_data);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * \brief TLS session_ticket extension
	 */
	struct session_ticket final: extension_base {

		std::string data;

		explicit session_ticket(std::string_view data);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * \brief TLS record_size_limit extension
	 */
	struct record_size_limit final: extension_base {

		uint16_t limit;

		explicit record_size_limit(uint16_t);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	/**
	 * \brief TLS application_layer_protocol_negotiation extension
	 */
	struct alpn final: extension_base {

		std::list<std::string> protocol_name_list;

		explicit alpn(std::list<std::string>);

		alpn(std::string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator raw_extension() const override;
	};


	std::optional<raw_extension> parse_extension(std::string_view& source);
}


template<>
struct std::formatter<leaf::network::tls::extension_base> {
	std::size_t indent = 0;

	constexpr auto parse(std::format_parse_context& context) {
		auto it = context.begin(), end = context.end();
		if (it != context.end() && '1' <= *it && *it <= '9')
			indent = std::strtoull(it, const_cast<char**>(&end), 10);
		return it;
	}

	std::format_context::iterator
	format(const leaf::network::tls::extension_base& extension, std::format_context& ctx) const {
		auto it = ctx.out();
		extension.format(it, indent);
		return it;
	}
};


template<>
struct std::formatter<leaf::network::tls::raw_extension> {

	constexpr auto parse(std::format_parse_context& context) {
		return context.begin();
	}

	std::format_context::iterator
	format(const leaf::network::tls::raw_extension& extension, std::format_context& ctx) const {
		return std::format_to(ctx.out(), "{} (raw extension, size={})", extension.type, extension.data.size());
	}
};
