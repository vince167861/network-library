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
		: tls::endpoint(client, endpoint_type_t::client, std::move(generator)), client_(client) {
	}

	bool client::connect(const std::string_view host, const uint16_t port) {
		close();
		reset();
		return client_.connect(host, port) && (handshake_(), true);
	}

	std::size_t client::available() {
		return app_data_buffer.view().size();
	}

	client_hello client::gen_client_hello_() const {
		client_hello clt_hl{available_cipher_suites_};
		switch (endpoint_version) {
			case protocol_version_t::TLS1_3:
				clt_hl.version = protocol_version_t::TLS1_2;
				break;
			default:
				throw std::runtime_error{"unimplemented"};
		}
		if (server_name)
			clt_hl.add_extension({tls::server_name{{server_name::name_type_t::host_name, server_name.value()}}});
		if (active_manager_)
			clt_hl.add_extension({
				key_share{key_share::msg_type_t::client_hello, {
					{active_manager_->group, active_manager_->public_key()}
				}}
			});
		else
			clt_hl.add_extension({
				key_share{key_share::msg_type_t::client_hello, available_managers_}
			});
		clt_hl.add_extension({
			supported_groups{available_groups_},
			supported_versions{supported_versions::msg_type_t::client_hello, {
					protocol_version_t::TLS1_3
			}},
			signature_algorithms{
					signature_scheme_t::ecdsa_secp256r1_sha256,
					signature_scheme_t::ecdsa_secp384r1_sha384,
					signature_scheme_t::ecdsa_secp521r1_sha512,
					signature_scheme_t::rsa_pss_rsae_sha256,
					signature_scheme_t::rsa_pss_rsae_sha384,
					signature_scheme_t::rsa_pss_rsae_sha512,
					signature_scheme_t::rsa_pkcs1_sha256,
					signature_scheme_t::rsa_pkcs1_sha384,
					signature_scheme_t::rsa_pkcs1_sha512
			},
			psk_key_exchange_modes{psk_key_exchange_mode_t::psk_dhe_ke},
			record_size_limit{16385},
		});
		if (!alpn_protocols.empty())
			clt_hl.add_extension({alpn{alpn_protocols}});
		std::ranges::copy(random, clt_hl.random.begin());
		clt_hl.session_id = session_id;
		return clt_hl;
	}

	void client::handshake_() {
		std::string handshake_msgs, cert_verify;
		{
			const auto ch = gen_client_hello_();
			send_(record::construct(content_type_t::handshake, std::nullopt, ch));
			handshake_msgs = ch.to_bytestring();
		}
		client_state_t client_state = client_state_t::wait_server_hello;
		while (client_state != client_state_t::connected) {
			auto record = record::extract(client_, cipher_);
			std::cout << std::format("[TLS client] got {}\n", record);
			switch (record.type) {
				case content_type_t::handshake:
					for (std::string_view handshake_fragments{record.messages}; !handshake_fragments.empty(); ) {
						const auto opt_message = parse_handshake(*this, handshake_fragments, record.encrypted());
						if (!opt_message)
							break;
						auto& handshake_msg = opt_message.value();
						switch (client_state) {
							case client_state_t::wait_server_hello: {
								if (!std::holds_alternative<server_hello>(handshake_msg))
									throw alert::unexpected_message();
								auto& srv_hl = std::get<server_hello>(handshake_msg);
								std::cout << std::format("[TLS client] got {}\n", static_cast<const message&>(srv_hl));
								use_cipher(srv_hl.cipher_suite);
								if (srv_hl.is_hello_retry_request)
									handshake_msgs = message_hash(active_cipher_suite(), handshake_msgs);
								handshake_msgs += srv_hl.to_bytestring();
								if (!srv_hl.extensions.contains(ext_type_t::supported_versions))
									throw std::runtime_error{"unimplemented"};
								{
									supported_versions srv_sprt_vrsn{supported_versions::msg_type_t::server_hello,
										srv_hl.extensions.at(ext_type_t::supported_versions)};
									if (!std::ranges::contains(srv_sprt_vrsn.versions, protocol_version_t::TLS1_3))
										throw std::runtime_error{"unimplemented"};
								}
								if (!srv_hl.extensions.contains(ext_type_t::key_share))
									throw alert::handshake_failure();
								key_share srv_key_shr{
										srv_hl.is_hello_retry_request ? key_share::msg_type_t::hello_retry_request : key_share::msg_type_t::server_hello,
										srv_hl.extensions.at(ext_type_t::key_share)};
								auto& [group, key] = *srv_key_shr.shares.begin();
								std::cout << std::format("[TLS client] using group {} for key exchange\n", group);
								if (available_managers_.contains(group)) {
									std::unique_ptr<key_exchange_manager> mgr;
									std::swap(available_managers_.at(group), mgr);
									use_group(std::move(mgr));
								} else
									use_group(group);
								if (srv_hl.is_hello_retry_request) {
									const auto ch = gen_client_hello_();
									send_(record::construct(content_type_t::handshake, std::nullopt, ch));
									handshake_msgs += ch.to_bytestring();
								} else {
									cipher_.update_entropy_secret(pre_shared_key); // todo: should calculate before wait_server_hello?
									active_manager().exchange_key(key);
									cipher_.update_entropy_secret(active_manager().shared_key());
									cipher_.update_key_iv(handshake_msgs);
									client_state = client_state_t::wait_encrypted_extensions;
								}
								break;
							}
							case client_state_t::wait_encrypted_extensions: {
								if (!std::holds_alternative<encrypted_extension>(handshake_msg))
									throw alert::unexpected_message();
								handshake_msgs += std::get<encrypted_extension>(handshake_msg).to_bytestring();
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
								handshake_msgs += std::get<certificate>(handshake_msg).to_bytestring();
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
								handshake_msgs += std::get<certificate_verify>(handshake_msg).to_bytestring();
								client_state = client_state_t::wait_finish;
								break;
							case client_state_t::wait_finish: {
								if (!std::holds_alternative<finished>(handshake_msg))
									throw alert::unexpected_message();
								handshake_msgs += std::get<finished>(handshake_msg).to_bytestring();
								auto& cipher = active_cipher_suite();
								send_(record::construct(content_type_t::handshake, cipher_, finished{
										cipher.HMAC_hash(
												cipher.hash(handshake_msgs),
												cipher.HKDF_expand_label(
														cipher_.client_handshake_traffic_secret,
														"finished", "", cipher.digest_length)),
										cipher}));

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
			session_id = random_generator->number(32).to_bytestring(std::endian::big);
		else
			session_id.clear();
	}
}
