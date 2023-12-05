#pragma once

#include "tls-extension/extension.h"
#include "tls-cipher/cipher_suite.h"
#include "tls-context/context.h"

#include <list>

namespace leaf::network::tls {

	class handshake: public record {

		virtual std::string build_handshake_() const = 0;

	public:
		enum class handshake_type_t: uint8_t {
			client_hello = 1, server_hello = 2, new_session_ticket = 4, end_of_early_data = 5, encrypted_extensions = 8,
			certificate = 11, certificate_request = 13, certificate_verify = 15, finished = 20, key_update = 24,
			message_hash = 254
		};

		handshake_type_t handshake_type;
		// uint24_t length;
		// ...

		handshake(handshake_type_t, bool encrypted);

		std::string build_content_() final;

		static std::shared_ptr<handshake>
		parse(context& context, std::string_view::const_iterator& source, bool encrypted);
	};


	/**
	 * TLS "ClientHello" handshake message
	 * Structure:
	 * 	uint16_t legacy_version
	 * 	opaque random[32]
	 * 	opaque legacy_session_id<0..32>
	 * 	cipher_suite_t cipher_suites<2..2^16-2>
	 * 	opaque legacy_compression_methods<1..2^8-1>
	 * 	extension extensions<8..2^16-1>
	 */
	class client_hello: public handshake {

		void print(std::ostream& ostream) const override;

	public:
		protocol_version_t legacy_version = protocol_version_t::TLS1_2;
		random_t random;
		std::string legacy_session_id;
		std::list<cipher_suite_t> cipher_suites;
		std::string legacy_compression_methods;
		std::list<std::shared_ptr<extension>> extensions;

		client_hello(const context& context);

		client_hello(std::string_view, context&);

		std::string build_handshake_() const override;
	};


	/**
	 * TLS "ServerHello" handshake message
	 */
	class server_hello: public handshake {

		void print(std::ostream& ostream) const override;

	public:
		protocol_version_t legacy_version = protocol_version_t::TLS1_2;
		random_t random;
		std::string legacy_session_id_echo; // 0..32 bytes
		cipher_suite_t cipher_suite;
		uint8_t legacy_compression_method = 0;
		std::list<std::shared_ptr<extension>> extensions; // 6..2^16-1 bytes

		bool is_hello_retry_request = false;

		server_hello();

		server_hello(std::string_view, context&);

		std::string build_handshake_() const override;
	};


	/**
	 * TLS "EncryptedExtensions" handshake message
	 */
	class encrypted_extension: public handshake {
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		std::list<std::shared_ptr<extension>> extensions;

		encrypted_extension(std::string_view, context&);
	};


	/**
	 * TLS "Certificate" handshake message
	 */
	class certificate: public handshake {
	public:
	private:
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		struct certificate_entry {
			std::string data;
			std::list<std::shared_ptr<extension>> extensions;
		};

		std::string certificate_request_context;

		std::list<certificate_entry> certificate_list;

		certificate(std::string_view, context&);
	};


	/**
	 * TLS "CertificateRequest" handshake message
	 */
	class certificate_request: public handshake {
	public:
		std::string certificate_request_context;

		std::list<std::shared_ptr<extension>> extensions;

		certificate_request(std::string_view, context&);
	};


	class certificate_verify: public handshake {
	public:
	private:
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		signature_scheme_t signature_scheme;

		std::string signature;

		certificate_verify(std::string_view);
	};


	class finished: public handshake {
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		std::string verify_data;

		finished(context&, std::string_view handshake_msgs);

		finished(std::string_view source, context&);
	};


	class new_session_ticket: public handshake {
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		uint32_t ticket_lifetime;

		uint32_t ticket_age_add;

		std::string ticket_nonce;

		std::string ticket;

		std::list<std::shared_ptr<extension>> extensions;

		new_session_ticket(std::string_view, context&);
	};


	class key_update: public handshake {
		std::string build_handshake_() const override;

		void print(std::ostream& ostream) const override;

	public:
		enum class key_update_request: uint8_t {
			update_not_requested = 0, update_requested = 1
		} request_update;

		key_update(std::string_view);

		key_update(bool request);
	};

	std::string message_hash(cipher_suite&, client_hello&);
}
