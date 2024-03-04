#pragma once
#include "tls-extension/extension.h"
#include "tls-record/record.h"
#include "tls/cipher/cipher_suite.h"
#include <map>
#include <list>
#include <set>
#include <expected>

namespace network::tls {

	struct handshake_base: message {};

	struct extension_holder {

		std::map<ext_type_t, std::unique_ptr<extension_base>> extensions;

		std::list<ext_type_t> extensions_order;

		void add(ext_type_t, std::unique_ptr<extension_base>);

		const extension_base& get(ext_type_t) const;

		template<class T> requires std::is_base_of_v<extension_base, T>
		const T& get(const ext_type_t __t) const {
			return reinterpret_cast<const std::remove_cvref_t<T>&>(get(__t));
		}
	};


	struct client_hello final: handshake_base, extension_holder {

		protocol_version_t version;

		random_t random;

		byte_string session_id;

		std::list<cipher_suite_t> cipher_suites;

		byte_string compression_methods;

		client_hello(std::set<cipher_suite_t>);

		client_hello(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct server_hello final: handshake_base, extension_holder {

		protocol_version_t version;

		random_t random;

		byte_string session_id_echo;

		cipher_suite_t cipher_suite;

		std::uint8_t compression_method;

		server_hello() = default;

		server_hello(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;

		bool is_hello_retry_request = false;

		void to_retry();
	};


	struct encrypted_extension final: handshake_base, extension_holder {

		encrypted_extension() = default;

		encrypted_extension(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct certificate final: handshake_base {

		struct certificate_entry: extension_holder {

			byte_string data;
		};

		byte_string certificate_request_context;

		std::list<certificate_entry> certificate_list;

		certificate() = default;

		certificate(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct certificate_request final: handshake_base, extension_holder {

		byte_string certificate_request_context;

		certificate_request(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct certificate_verify final: handshake_base {

		signature_scheme_t signature_scheme;

		byte_string signature;

		certificate_verify(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct finished final: handshake_base {

		byte_string verify_data;

		finished(byte_string_view source);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct new_session_ticket final: handshake_base, extension_holder {

		uint32_t ticket_lifetime;

		uint32_t ticket_age_add;

		byte_string ticket_nonce;

		byte_string ticket;

		new_session_ticket(byte_string_view);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct key_update final: handshake_base {

		enum class key_update_request: uint8_t {
			update_not_requested = 0, update_requested = 1
		} request_update;

		key_update(byte_string_view);

		key_update(bool request);

		operator byte_string() const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};

	byte_string message_hash(const cipher_suite&, byte_string_view);

	using handshake = std::variant<client_hello, server_hello, encrypted_extension, certificate, certificate_request,
			certificate_verify, finished, new_session_ticket, key_update>;

	std::expected<handshake, std::string>
	parse_handshake(byte_string_view& source, bool encrypted, bool established);
}


template<>
struct std::formatter<network::tls::handshake> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	std::format_context::iterator format(const network::tls::handshake& msg, std::format_context& ctx) const {
		return std::visit([&](const auto& typed_msg){ return typed_msg.format(ctx.out()); }, msg);
	}
};
