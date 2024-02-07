#pragma once

#include "tls-extension/extension.h"
#include "tls-record/record.h"
#include "tls-cipher/cipher_suite.h"

#include <map>
#include <list>
#include <set>

namespace leaf::network::tls {


	enum class handshake_type_t: std::uint8_t {
		client_hello = 1, server_hello = 2, new_session_ticket = 4, end_of_early_data = 5, encrypted_extensions = 8,
		certificate = 11, certificate_request = 13, certificate_verify = 15, finished = 20, key_update = 24,
		message_hash = 254
	};


	struct handshake_base: message {};


	/**
	 * TLS "ClientHello" handshake_ message
	 */
	struct client_hello final: handshake_base {

		/** legacy_version */
		protocol_version_t version;

		random_t random;

		/** legacy_session_id */
		std::string session_id;

		std::list<cipher_suite_t> cipher_suites;

		/** legacy_compression_methods */
		std::string compression_methods;

		std::map<ext_type_t, std::string> extensions;

		client_hello(std::set<cipher_suite_t>);

		client_hello(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;

		void add_extension(std::initializer_list<raw_extension>);

	private:
		std::list<ext_type_t> extension_order_;
	};


	/**
	 * TLS "ServerHello" handshake_ message
	 */
	struct server_hello final: handshake_base {

		/** legacy_version */
		protocol_version_t version;

		random_t random;

		/** legacy_session_id_echo */
		std::string session_id_echo;

		cipher_suite_t cipher_suite;

		/** legacy_compression_method */
		std::uint8_t compression_method;

		std::map<ext_type_t, std::string> extensions;

		server_hello() = default;

		server_hello(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;

		bool is_hello_retry_request = false;

		void to_retry();

		void add_extension(std::initializer_list<raw_extension>);

	private:
		std::list<ext_type_t> extension_order_;
	};


	/**
	 * \brief TLS "EncryptedExtensions" handshake_ message
	 * \note Encryption required
	 */
	struct encrypted_extension final: handshake_base {

		std::map<ext_type_t, std::string> extensions;

		encrypted_extension() = default;

		encrypted_extension(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;

	private:
		std::list<ext_type_t> extension_order_;
	};


	/**
	 * TLS "Certificate" handshake_ message
	 */
	struct certificate final: handshake_base {

		struct certificate_entry {
			std::string data;
			std::list<raw_extension> extensions;
		};

		std::string certificate_request_context;

		std::list<certificate_entry> certificate_list;

		certificate() = default;

		certificate(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	/**
	 * \brief A TLS "CertificateRequest" handshake_ message.
	 * \note Encryption required.
	 */
	struct certificate_request final: handshake_base {

		std::string certificate_request_context;

		std::list<raw_extension> extensions;

		certificate_request(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	/**
	 * \brief A TLS "CertificateVerify" handshake_ message.
	 * \note Encryption required.
	 */
	struct certificate_verify final: handshake_base {

		signature_scheme_t signature_scheme;

		std::string signature;

		certificate_verify(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	/**
	 * \brief A TLS "Finished" handshake_ message.
	 * \note Encryption required.
	 */
	struct finished final: handshake_base {

		std::string verify_data;

		finished(std::string_view source, cipher_suite&);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct new_session_ticket final: handshake_base {

		uint32_t ticket_lifetime;

		uint32_t ticket_age_add;

		std::string ticket_nonce;

		std::string ticket;

		std::list<raw_extension> extensions;

		new_session_ticket(std::string_view);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct key_update final: handshake_base {

		enum class key_update_request: uint8_t {
			update_not_requested = 0, update_requested = 1
		} request_update;

		key_update(std::string_view);

		key_update(bool request);

		std::string to_bytestring(std::endian = std::endian::big) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};

	std::string message_hash(const cipher_suite&, std::string_view);

	using handshake = std::variant<client_hello, server_hello, encrypted_extension, certificate, certificate_request,
			certificate_verify, finished, new_session_ticket, key_update>;

	class endpoint;

	std::optional<handshake> parse_handshake(tls::endpoint&, std::string_view& source, bool encrypted, bool established);
}


template<>
struct std::formatter<leaf::network::tls::handshake> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	std::format_context::iterator format(const leaf::network::tls::handshake&, std::format_context& ctx) const;
};
