#include "tls/client.h"

#include "tls-context/endpoint.h"
#include "tls-record/alert.h"
#include "tls-record/record.h"
#include "tls-extension/extension.h"

#include "utils.h"
#include <iostream>
#include <ranges>

namespace leaf::network::tls {

	client::client(network::client& client, std::unique_ptr<random_number_generator> generator)
		: endpoint(client, endpoint_type_t::client, std::move(generator)), client_(client) {
	}

	bool client::connect(const std::string_view host, const uint16_t port) {
		close();
		reset();
		return client_.connect(host, port) && (handshake_(), true);
	}

	std::size_t client::available() {
		return app_data_buffer.size();
	}

	std::unique_ptr<client_hello> client::gen_client_hello_() const {
		client_hello clt_hl(available_cipher_suites_);
		switch (endpoint_version) {
			case protocol_version_t::TLS1_3:
				clt_hl.version = protocol_version_t::TLS1_2;
				break;
			default:
				throw std::runtime_error("unimplemented");
		}
		if (server_name)
			clt_hl.add(
				ext_type_t::server_name,
				std::make_unique<struct server_name>(tls::server_name{{server_name::name_type_t::host_name, server_name.value()}}));
		if (active_manager_)
			clt_hl.add(ext_type_t::key_share, std::make_unique<key_share>(key_share(extension_holder_t::client_hello, {{active_manager_->group, active_manager_->public_key()}})));
		else
			clt_hl.add(ext_type_t::key_share, std::make_unique<key_share>(extension_holder_t::client_hello, available_managers_));
		clt_hl.add(ext_type_t::supported_groups, std::make_unique<supported_groups>(available_groups_));
		clt_hl.add(ext_type_t::supported_versions, std::make_unique<supported_versions>(extension_holder_t::client_hello, std::initializer_list<protocol_version_t>{protocol_version_t::TLS1_3}));
		clt_hl.add(ext_type_t::signature_algorithms, std::make_unique<signature_algorithms>(std::initializer_list<signature_scheme_t>{
				signature_scheme_t::ecdsa_secp256r1_sha256,
				signature_scheme_t::ecdsa_secp384r1_sha384,
				signature_scheme_t::ecdsa_secp521r1_sha512,
				signature_scheme_t::rsa_pss_rsae_sha256,
				signature_scheme_t::rsa_pss_rsae_sha384,
				signature_scheme_t::rsa_pss_rsae_sha512,
				signature_scheme_t::rsa_pkcs1_sha256,
				signature_scheme_t::rsa_pkcs1_sha384,
				signature_scheme_t::rsa_pkcs1_sha512
		}));
		clt_hl.add(ext_type_t::psk_key_exchange_modes, std::make_unique<psk_key_exchange_modes>(psk_key_exchange_modes{psk_key_exchange_mode_t::psk_dhe_ke}));
		clt_hl.add(ext_type_t::record_size_limit, std::make_unique<record_size_limit>(16385));
		if (!alpn_protocols.empty())
			clt_hl.add(ext_type_t::alpn, std::make_unique<alpn>(alpn_protocols));
		clt_hl.random = random;
		clt_hl.session_id = session_id;
		return std::make_unique<client_hello>(std::move(clt_hl));
	}

	void client::handshake_() {
		byte_string handshake_msgs, cert_verify;
		{
			auto ch = gen_client_hello_();
			handshake_msgs += *ch;
			send_(content_type_t::handshake, false, {std::move(ch)});
		}
		client_state_t client_state = client_state_t::wait_server_hello;
		while (client_state != client_state_t::connected) {
			auto record = record::extract(client_, cipher_);
			std::cout << std::format("[TLS client] got {}\n", record);
			switch (record.type) {
				case content_type_t::handshake:
					for (byte_string_view handshake_fragments{record.messages}; !handshake_fragments.empty(); ) {
						const auto opt_message = parse_handshake(*this, handshake_fragments, record.encrypted(), false);
						if (!opt_message)
							break;
						auto& handshake_msg = opt_message.value();
						std::cout << std::format("[TLS client] got {}\n", handshake_msg);
						switch (client_state) {
							case client_state_t::wait_server_hello: {
								if (!std::holds_alternative<server_hello>(handshake_msg))
									throw alert::unexpected_message();
								auto& srv_hl = std::get<server_hello>(handshake_msg);
								use_cipher(srv_hl.cipher_suite);
								if (srv_hl.is_hello_retry_request)
									handshake_msgs = message_hash(active_cipher_suite(), handshake_msgs);
								handshake_msgs += srv_hl;

								if (!srv_hl.extensions.contains(ext_type_t::supported_versions))
									throw std::runtime_error("unimplemented");
								auto& __s_sv = srv_hl.get<supported_versions>(ext_type_t::supported_versions);
								if (!std::ranges::contains(__s_sv.versions, protocol_version_t::TLS1_3))
									throw std::runtime_error("unimplemented");

								if (!srv_hl.extensions.contains(ext_type_t::key_share))
									throw alert::handshake_failure();
								auto& __s_ks = srv_hl.get<key_share>(ext_type_t::key_share);
								auto& [group, key] = *__s_ks.shares.begin();
								std::cout << std::format("[TLS client] using group {} for key exchange\n", group);
								if (available_managers_.contains(group)) {
									std::unique_ptr<key_exchange_manager> mgr;
									std::swap(available_managers_.at(group), mgr);
									use_group(std::move(mgr));
								} else
									use_group(group);
								if (srv_hl.is_hello_retry_request) {
									auto ch = gen_client_hello_();
									handshake_msgs += *ch;
									send_(content_type_t::handshake, false, {std::move(ch)});
								} else {
									cipher_.update_entropy_secret(pre_shared_key); // todo: should calculate before wait_server_hello?
									active_manager().exchange(key);
									cipher_.update_entropy_secret(active_manager().shared_key());
									cipher_.update_key_iv(handshake_msgs);
									client_state = client_state_t::wait_encrypted_extensions;
								}
								break;
							}
							case client_state_t::wait_encrypted_extensions: {
								if (!std::holds_alternative<encrypted_extension>(handshake_msg))
									throw alert::unexpected_message();
								auto& srv_enc_ext = std::get<encrypted_extension>(handshake_msg);
								if (!alpn_protocols.empty()) {
									if (!srv_enc_ext.extensions.contains(ext_type_t::alpn))
										throw std::runtime_error{"server does not support ALPN"};
									auto& __s_alpn = srv_enc_ext.get<alpn>(ext_type_t::alpn);
									std::cout << std::format("[TLS client] ALPN selected: {}\n", __s_alpn.protocol_name_list.front());
								}
								handshake_msgs += std::get<encrypted_extension>(handshake_msg);
								client_state = client_state_t::wait_cert_request;
								break;
							}
							case client_state_t::wait_cert_request:
								if (std::holds_alternative<certificate_request>(handshake_msg)) {
									client_state = client_state_t::wait_cert;
									break;
								}
								[[fallthrough]];
							case client_state_t::wait_cert:
								if (!std::holds_alternative<certificate>(handshake_msg))
									throw alert::unexpected_message();
								handshake_msgs += std::get<certificate>(handshake_msg);
								/* auto&& cert_verify_content
										= std::string(64, ' ')
												+ "TLS 1.3, server CertificateVerify"
												+ '\0'
												+ active_cipher().hash(handshake_msgs); */
								client_state = client_state_t::wait_cert_verify;
								break;
							case client_state_t::wait_cert_verify:
								if (!std::holds_alternative<certificate_verify>(handshake_msg))
									throw alert::unexpected_message();
								handshake_msgs += std::get<certificate_verify>(handshake_msg);
								client_state = client_state_t::wait_finish;
								break;
							case client_state_t::wait_finish: {
								if (!std::holds_alternative<finished>(handshake_msg))
									throw alert::unexpected_message();
								handshake_msgs += std::get<finished>(handshake_msg);
								auto& cipher = active_cipher_suite();
								send_(content_type_t::handshake, true, {
									std::make_unique<finished>(
											cipher.HMAC_hash(
													cipher.hash(handshake_msgs),
													cipher.HKDF_expand_label(
															cipher_.client_handshake_traffic_secret,
															reinterpret_cast<const uint8_t*>("finished"),
															reinterpret_cast<const uint8_t*>(""),
															cipher.digest_length)),
											cipher)});

								client_state = client_state_t::connected;
								cipher_.update_entropy_secret();
								cipher_.update_key_iv(handshake_msgs);
								break;
							}
							default:
								throw alert::unexpected_message();
						}
					}
					break;
				case content_type_t::change_cipher_spec:
					break;
				case content_type_t::alert:
					std::cout << std::format("[TLS client] got {}\n", static_cast<message&&>(alert{record.messages}));
					throw std::runtime_error{"got alert"};
				default:
					throw alert::unexpected_message();
			}
		}
	}

	void client::add_group(std::initializer_list<named_group_t> groups) {
		for (auto group: groups)
			available_managers_.emplace(group, get_key_manager(group, *random_generator));
		available_groups_.insert(groups.begin(), groups.end());
	}

	void client::add_cipher_suite(std::initializer_list<cipher_suite_t> suites) {
		available_cipher_suites_.insert(suites.begin(), suites.end());
	}

	void client::reset() {
		if (init_random)
			std::ranges::copy(init_random.value(), random.begin());
		else for (auto& i : random)
			i = random_generator->unit();
		if (init_session_id)
			session_id = init_session_id.value();
		else if (compatibility_mode)
			session_id = random_generator->number(32);
		else
			session_id.clear();
	}
}
