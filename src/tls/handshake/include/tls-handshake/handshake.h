#pragma once

#include "tls-extension/extension.h"
#include "tls-record/record.h"
#include "tls-cipher/cipher_suite.h"
#include "tls-context/context.h"

#include <list>

namespace leaf::network::tls {


	enum class handshake_type_t: std::uint8_t {
		client_hello = 1, server_hello = 2, new_session_ticket = 4, end_of_early_data = 5, encrypted_extensions = 8,
		certificate = 11, certificate_request = 13, certificate_verify = 15, finished = 20, key_update = 24,
		message_hash = 254
	};


	struct handshake_base: message {};


	/**
	 * TLS "ClientHello" handshake message
	 */
	struct client_hello final: handshake_base {

		protocol_version_t legacy_version = protocol_version_t::TLS1_2;
		random_t random;
		std::string legacy_session_id;
		std::list<cipher_suite_t> cipher_suites;
		std::string legacy_compression_methods;
		std::list<raw_extension> extensions;

		client_hello(const context& context);

		client_hello(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	/**
	 * TLS "ServerHello" handshake message
	 */
	struct server_hello final: handshake_base {

		protocol_version_t legacy_version = protocol_version_t::TLS1_2;
		random_t random;
		std::string legacy_session_id_echo; // 0..32 bytes
		cipher_suite_t cipher_suite;
		uint8_t legacy_compression_method = 0;
		std::list<raw_extension> extensions; // 6..2^16-1 bytes

		bool is_hello_retry_request = false;

		server_hello() = default;

		server_hello(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;

	};


	/**
	 * \brief TLS "EncryptedExtensions" handshake message
	 * \note Encryption required
	 */
	struct encrypted_extension final: handshake_base {

		std::list<raw_extension> extensions;

		encrypted_extension(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	/**
	 * TLS "Certificate" handshake message
	 */
	struct certificate final: handshake_base {

		struct certificate_entry {
			std::string data;
			std::list<raw_extension> extensions;
		};

		std::string certificate_request_context;

		std::list<certificate_entry> certificate_list;

		certificate(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	/**
	 * \brief A TLS "CertificateRequest" handshake message.
	 * \note Encryption required.
	 */
	struct certificate_request final: handshake_base {

		std::string certificate_request_context;

		std::list<raw_extension> extensions;

		certificate_request(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	/**
	 * \brief A TLS "CertificateVerify" handshake message.
	 * \note Encryption required.
	 */
	struct certificate_verify final: handshake_base {

		signature_scheme_t signature_scheme;

		std::string signature;

		certificate_verify(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	/**
	 * \brief A TLS "Finished" handshake message.
	 * \note Encryption required.
	 */
	struct finished final: handshake_base {

		std::string verify_data;

		finished(context&, std::string_view handshake_msgs);

		finished(std::string_view source, context&);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	struct new_session_ticket final: handshake_base {

		uint32_t ticket_lifetime;

		uint32_t ticket_age_add;

		std::string ticket_nonce;

		std::string ticket;

		std::list<raw_extension> extensions;

		new_session_ticket(std::string_view);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};


	struct key_update final: handshake_base {

		enum class key_update_request: uint8_t {
			update_not_requested = 0, update_requested = 1
		} request_update;

		key_update(std::string_view);

		key_update(bool request);

		std::string to_bytestring() const override;

		void format(std::format_context::iterator&) const override;
	};

	std::string message_hash(const cipher_suite&, std::string_view);

	using handshake = std::variant<client_hello, server_hello, encrypted_extension, certificate, certificate_request,
			certificate_verify, finished, new_session_ticket, key_update>;

	std::optional<handshake> parse_handshake(context&, std::string_view& source, bool encrypted);
}
