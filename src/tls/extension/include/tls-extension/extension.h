#pragma once
#include "common.h"
#include "tls-key/manager.h"
#include "tls-utils/type.h"
#include <memory>
#include <set>
#include <map>
#include <list>
#include <expected>

namespace leaf::network::tls {

	struct extension_base {

		virtual void format(std::format_context::iterator&, std::size_t level) const = 0;

		virtual operator byte_string() const = 0;

		virtual ~extension_base() = default;
	};


	struct raw_extension final: extension_base {

		ext_type_t type;

		byte_string data;

		raw_extension(ext_type_t, byte_string_view);

		void format(std::format_context::iterator& iterator, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct supported_versions final: extension_base {

		extension_holder_t holder_type;

		std::list<protocol_version_t> versions;

		supported_versions(extension_holder_t, byte_string_view);

		supported_versions(extension_holder_t, std::initializer_list<protocol_version_t>);

		void format(std::format_context::iterator& it, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct key_share final: extension_base {

		extension_holder_t holder_type;

		std::map<named_group_t, byte_string> shares;

		key_share(extension_holder_t, const std::map<named_group_t, std::unique_ptr<key_exchange_manager>>&);

		key_share(extension_holder_t, std::map<named_group_t, byte_string>);

		key_share(extension_holder_t, byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct supported_groups final: extension_base {

		std::list<named_group_t> named_group_list;

		supported_groups(const std::set<named_group_t>&);

		supported_groups(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct signature_algorithms final: extension_base {

		std::list<signature_scheme_t> list;

		signature_algorithms(std::initializer_list<signature_scheme_t>);

		signature_algorithms(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct psk_key_exchange_modes final: extension_base {

		std::list<psk_key_exchange_mode_t> modes;

		psk_key_exchange_modes(std::initializer_list<psk_key_exchange_mode_t>);

		psk_key_exchange_modes(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct server_name final: extension_base {

		enum class name_type_t: uint8_t {
			host_name = 0
		};

		std::list<std::pair<name_type_t, std::string>> server_name_list;

		server_name(std::initializer_list<std::pair<name_type_t, std::string>>);

		server_name(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct renegotiation_info final: extension_base {

		byte_string renegotiated_connection;

		explicit renegotiation_info(byte_string_view verify_data);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct session_ticket final: extension_base {

		byte_string data;

		session_ticket(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct record_size_limit final: extension_base {

		std::uint16_t limit;

		record_size_limit(std::uint16_t);

		record_size_limit(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	struct alpn final: extension_base {

		std::list<std::string> protocol_name_list;

		alpn(std::list<std::string>);

		alpn(byte_string_view);

		void format(std::format_context::iterator&, std::size_t level) const override;

		operator byte_string() const override;
	};


	std::expected<std::pair<ext_type_t, std::unique_ptr<extension_base>>, std::string>
	parse_extension(byte_string_view&, extension_holder_t);
}


template<>
struct std::formatter<leaf::network::tls::extension_base> {

	std::size_t indent = 0;

	constexpr auto parse(std::format_parse_context& ctx) {
		const auto it = ctx.begin(), end = ctx.end();
		if (it != end)
			if (std::from_chars(it, end, indent).ec != std::errc())
				throw std::format_error("formatting extension: indent error");
		return it;
	}

	std::format_context::iterator
	format(const leaf::network::tls::extension_base& extension, std::format_context& ctx) const {
		auto it = ctx.out();
		extension.format(it, indent);
		return it;
	}
};
