#pragma once

#include "tls-record/record.h"

namespace leaf::network::tls {

	enum class ext_type_t: uint16_t {
		server_name = 0, max_fragment_length = 1, status_request = 5, supported_groups = 10,
		signature_algorithms = 13, use_srtp = 14, heartbeat = 15, alpn = 16,
		signed_cert_timestamp = 18, client_cert_type = 19, server_cert_type = 20,
		padding = 21, record_size_limit = 28, session_ticket = 35, pre_shared_key = 41, early_data = 42, supported_versions = 43,
		cookie = 44, psk_key_exchange_modes = 45, cert_authorities = 47, oid_filters = 48,
		post_handshake_auth = 49, signature_algorithms_cert = 50, key_share = 51,
		renegotiation_info = 0xff01
	};

	/**
	 * base class of TLS handshake messages
	 */
	class extension {
		virtual std::string build_() const = 0;

	public:
		const ext_type_t extension_type;

		explicit extension(ext_type_t);

		std::string build() const;

		[[nodiscard]]
		static extension* parse(context& context, std::string_view::const_iterator&, record&);

		virtual void print(std::ostream&, std::size_t level) const = 0;

		friend std::ostream& operator<<(std::ostream&, const extension&);

		virtual ~extension() = default;
	};


	/**
	 * TLS supported_version extension
	 */
	class supported_versions final: public extension {

		std::string build_() const override;

		void print(std::ostream&, std::size_t level) const override;

	public:
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
	};


	/**
	 * TLS key_share extension
	 */
	class key_share: public extension {

		std::string build_() const override;

		void print(std::ostream&, std::size_t level) const override;

	public:
		std::list<std::pair<named_group_t, std::string>> shares;

		enum class msg_type_t {
			client_hello,
			hello_retry_request,
			server_hello
		} message_type;

		explicit key_share(const context& context);

		key_share(std::string_view, bool is_hello_retry_request, context&);
	};


	/**
	 * TLS supported_groups extension.
	 */
	class supported_groups: public extension {

		std::string build_() const override;

		void print(std::ostream& ostream, std::size_t level) const override;

	public:
		enum class msg_type_t {
			client_hello,
			server_hello
		} message_type;

		std::list<named_group_t> named_group_list;

		explicit supported_groups(const context&);

		supported_groups(std::string_view, context&);
	};


	/**
	 * TLS signature_algorithms extension
	 */
	class signature_algorithms: public extension {

		std::string build_() const override;

		void print(std::ostream& ostream, std::size_t level) const override;

	public:
		std::list<signature_scheme_t> list;

		signature_algorithms(std::initializer_list<signature_scheme_t>);
	};


	/**
	 * TLS psk_key_exchange_modes extension
	 */
	class psk_key_exchange_modes: public extension {
		std::string build_() const override;

		void print(std::ostream& ostream, std::size_t level) const override;

	public:
		enum class psk_key_exchange_mode_t: uint8_t {
			psk_ke = 0,
			psk_dhe_ke = 1
		};

		std::list<psk_key_exchange_mode_t> modes;

		psk_key_exchange_modes(std::initializer_list<psk_key_exchange_mode_t>);
	};


	/**
	 * TLS server_name extension
	 */
	class server_name: public extension {
		std::string build_() const override;

		void print(std::ostream& ostream, std::size_t level) const override;

	public:
		enum class name_type_t: uint8_t {
			host_name = 0
		};

		std::list<std::pair<name_type_t, std::string>> server_name_list;

		server_name(std::initializer_list<std::pair<name_type_t, std::string>>);

		server_name(std::string_view);
	};


	/**
	 * \brief TLS renegotiation_info extension
	 */
	class renegotiation_info: public extension {
		std::string build_() const override;

		void print(std::ostream& ostream, std::size_t level) const override;

	public:
		std::string renegotiated_connection;

		explicit renegotiation_info(std::string_view verify_data);
	};


	/**
	 * \brief TLS session_ticket extension
	 */
	class session_ticket final: public extension {
		std::string build_() const override;

		void print(std::ostream&, std::size_t level) const override;

	public:
		std::string data;

		explicit session_ticket(std::string_view data);
	};


	/**
	 * \brief TLS record_size_limit extension
	 */
	class record_size_limit final: public extension {
		std::string build_() const override;

	public:
		void print(std::ostream&, std::size_t level) const override;

		uint16_t limit;

		explicit record_size_limit(uint16_t);
	};


	/**
	 * \brief TLS application_layer_protocol_negotiation extension
	 */
	class alpn final: public extension {
		std::string build_() const override;

	public:
		void print(std::ostream&, std::size_t level) const override;

		std::list<std::string> protocol_name_list;

		explicit alpn(std::list<std::string>);

		alpn(std::string_view);
	};
}
