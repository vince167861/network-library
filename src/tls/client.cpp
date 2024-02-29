#include "tls/client.h"
#include "tls-record/alert.h"
#include "tls-extension/extension.h"
#include "internal/utils.h"
#include <iostream>
#include <ranges>

namespace leaf::network::tls {

	constexpr std::uint8_t finished_label[] = "finished", empty_context[] = "";

	client::client(network::client& client, std::unique_ptr<random_number_generator> generator)
		: endpoint(client, endpoint_type_t::client, std::move(generator)), client_(client) {
	}

	void client::connect(const std::string_view host, const uint16_t port) {
		close();
		reset();
		client_.connect(host, port);
		handshake_();
	}

	std::size_t client::available() {
		return app_data_.size();
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
		if (key_exchange_)
			clt_hl.add(ext_type_t::key_share, std::make_unique<key_share>(key_share(extension_holder_t::client_hello, {{key_exchange_->group, key_exchange_->public_key()}})));
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
			auto record = record::extract(client_, secret_);
			std::cout << std::format("[TLS client] got {}\n", record);
			switch (record.type) {
				case content_type_t::handshake:
					for (byte_string_view __content{record.messages}; !__content.empty(); ) {
						const auto opt_message = parse_handshake(__content, record.encrypted(), false);
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
									handshake_msgs = message_hash(cipher(), handshake_msgs);
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
									auto mgr = std::move(available_managers_.extract(group).mapped());
									use_group(std::move(mgr));
								} else
									use_group(group);
								if (srv_hl.is_hello_retry_request) {
									auto ch = gen_client_hello_();
									handshake_msgs += *ch;
									send_(content_type_t::handshake, false, {std::move(ch)});
								} else {
									secret_.update_entropy_secret(pre_shared_key); // todo: should calculate before wait_server_hello?
									key_exchange().exchange(key);
									secret_.update_entropy_secret(key_exchange().shared_key());
									secret_.update_handshake_key(handshake_msgs);
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
								auto& __s_finished = std::get<finished>(handshake_msg);
								auto& __c = cipher();
								const auto __s_finished_key
										= __c.HKDF_expand_label(secret_.server_traffic_secret, finished_label, empty_context, __c.digest_length);
								if (__s_finished.verify_data != __c.HMAC_hash(__c.hash(handshake_msgs), __s_finished_key))
									throw alert::decrypt_error("Finished.verify_data does not match");
								handshake_msgs += __s_finished;
								const auto __c_finished_key
										= __c.HKDF_expand_label(secret_.client_traffic_secret, finished_label, empty_context, __c.digest_length);
								send_(content_type_t::handshake, true, {
									std::make_unique<finished>(__c.HMAC_hash(__c.hash(handshake_msgs), __c_finished_key))});

								client_state = client_state_t::connected;
								secret_.update_entropy_secret();
								secret_.update_master_key(handshake_msgs);
								secret_.update_entropy_secret();
								break;
							}
							default:
								throw alert::unexpected_message();
						}
					}
					break;
				case content_type_t::change_cipher_spec:
					break;
				case content_type_t::alert: {
					const auto out = std::format("got {}", static_cast<message&&>(alert(record.messages)));
					std::cout << std::format("[TLS client] {}\n", out);
					throw std::runtime_error(out);
				}
				default:
					throw alert::unexpected_message();
			}
		}
	}

	void client::add_group(named_group_t __g, const bool generate) {
		if (generate)
			available_managers_.emplace(__g, get_key_manager(__g, *random_));
		available_groups_.insert(__g);
	}

	void client::add_cipher_suite(std::initializer_list<cipher_suite_t> suites) {
		available_cipher_suites_.insert(suites.begin(), suites.end());
	}

	void client::reset() {
		if (init_random)
			std::ranges::copy(init_random.value(), random.begin());
		else for (auto& i : random)
			i = random_->unit();
		if (init_session_id)
			session_id = init_session_id.value();
		else if (compatibility_mode)
			session_id = random_->number(32);
		else
			session_id.clear();
		secret_.reset();
	}
}
