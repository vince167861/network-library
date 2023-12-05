#include "tls/client.h"

#include "tls-context/context.h"
#include "tls-record/alert.h"
#include "tls-extension/extension.h"

#include "utils.h"
#include <utility>
#include <iostream>

namespace leaf::network::tls {

	client::client(network::client& client, std::shared_ptr<random_number_generator> generator)
			: context(protocol_version_t::TLS1_3, client, endpoint_type_t::client), random_generator(std::move(generator)) {
	}

	void client::reset() {
		if (random_random)
			for (auto& i : random)
				i = random_generator->unit();
		if (init_session_id)
			session_id = init_session_id.value();
		else if (compatibility_mode)
			session_id = random_generator->number(32).to_bytes();
		else
			session_id.clear();
	}

	client_hello client::gen_client_hello() const {
		client_hello ch(*this);
		if (server_name)
			ch.extensions.emplace_back(new tls::server_name{{server_name::name_type_t::host_name, server_name.value()}});
		ch.extensions.emplace_back(new supported_groups(*this));
		ch.extensions.emplace_back(new key_share(*this));
		ch.extensions.emplace_back(new supported_versions(*this));
		ch.extensions.emplace_back(new signature_algorithms{
				signature_scheme_t::ecdsa_secp256r1_sha256,
				signature_scheme_t::ecdsa_secp384r1_sha384,
				signature_scheme_t::ecdsa_secp521r1_sha512,
				signature_scheme_t::rsa_pss_rsae_sha256,
				signature_scheme_t::rsa_pss_rsae_sha384,
				signature_scheme_t::rsa_pss_rsae_sha512,
				signature_scheme_t::rsa_pkcs1_sha256,
				signature_scheme_t::rsa_pkcs1_sha384,
				signature_scheme_t::rsa_pkcs1_sha512
		});
		ch.extensions.emplace_back(new psk_key_exchange_modes{psk_key_exchange_modes::psk_key_exchange_mode_t::psk_dhe_ke});
		ch.extensions.emplace_back(new record_size_limit(16385));
		if (!alpn_protocols.empty())
			ch.extensions.emplace_back(new alpn(alpn_protocols));
		std::copy_n(random, 32, ch.random);
		ch.legacy_session_id = session_id;
		return ch;
	}

	void client::handshake() {
		auto ch = gen_client_hello();
		send(ch);
		client_state = client_state_t::wait_server_hello;

		auto handshake_msgs = ch.build_content_();
		std::string early_secret, handshake_secret, master_secret, cert_verify;
		while (client_state != client_state_t::connected && client_state != client_state_t::closed) {
			try {
				record::parse(*this, [&](record& msg){
					std::cout << "Received record " << msg;
					switch (msg.type) {
						case record::content_type_t::handshake: {
							auto& hs_msg = reinterpret_cast<class handshake&>(msg);
							switch (client_state) {
								case client_state_t::wait_server_hello: {
									if (hs_msg.handshake_type == handshake::handshake_type_t::server_hello) {
										auto& hs_sh = reinterpret_cast<server_hello&>(msg);
										use_cipher(hs_sh.cipher_suite);
										if (hs_sh.is_hello_retry_request)
											handshake_msgs = message_hash(active_cipher(), ch);
										handshake_msgs += hs_sh.build_content_();
										if (hs_sh.is_hello_retry_request) {
											for (auto& ext: hs_sh.extensions) {
												if (ext->extension_type == ext_type_t::key_share) {
													auto& key_share_ext = reinterpret_cast<key_share&>(*ext);
													auto& [group, key] = key_share_ext.shares.front();
													use_group(group);
													active_manager().generate_private_key(*random_generator);
												}
											}
											auto ch2 = gen_client_hello();
											send(ch2);
											handshake_msgs += ch2.build_content_();
										}
										else {
											const auto& cipher = active_cipher();
											early_secret = cipher.HMAC_hash(
												pre_shared_key.empty()
													? std::string(cipher.digest_length, 0)
													: pre_shared_key,
												""); // todo: should calculate before wait_server_hello?
											for (auto& ext: hs_sh.extensions) {
												if (ext->extension_type == ext_type_t::key_share) {
													auto& key_share_ext = *std::reinterpret_pointer_cast<
														key_share>(ext);
													auto& [group, key] = key_share_ext.shares.front();
													use_group(group);
													active_manager().exchange_key(key);
												}
											}
											client_state = client_state_t::wait_encrypted_extensions;
											handshake_secret = cipher.HMAC_hash(
												active_manager().shared_key(),
												cipher.derive_secret(early_secret, "derived", ""));
											client_handshake_traffic_secret = var_unsigned::from_bytes(
												cipher.derive_secret(handshake_secret, "c hs traffic", handshake_msgs));
											server_handshake_traffic_secret = var_unsigned::from_bytes(
												cipher.derive_secret(handshake_secret, "s hs traffic", handshake_msgs));
											update_key_iv();
										}
										break;
									}
									throw alert::unexpected_message();
								}
								case client_state_t::wait_encrypted_extensions:
									if (hs_msg.handshake_type == handshake::handshake_type_t::encrypted_extensions) {
										handshake_msgs += hs_msg.build_content_();
										client_state = client_state_t::wait_cert_request;
										break;
									}
									throw alert::unexpected_message();
								case client_state_t::wait_cert_request:
									if (hs_msg.handshake_type == handshake::handshake_type_t::certificate_request) {
										client_state = client_state_t::wait_cert;
										break;
									}
									[[fallthrough]];
								case client_state_t::wait_cert:
									if (hs_msg.handshake_type == handshake::handshake_type_t::certificate) {
										handshake_msgs += hs_msg.build_content_();
										/* auto&& cert_verify_content
												= std::string(64, ' ')
														+ "TLS 1.3, server CertificateVerify"
														+ '\0'
														+ active_cipher().hash(handshake_msgs); */
										client_state = client_state_t::wait_cert_verify;
										break;
									}
									throw alert::unexpected_message();
								case client_state_t::wait_cert_verify:
									if (hs_msg.handshake_type == handshake::handshake_type_t::certificate_verify) {
										handshake_msgs += hs_msg.build_content_();
										client_state = client_state_t::wait_finish;
										break;
									}
									throw alert::unexpected_message();
								case client_state_t::wait_finish:
									if (hs_msg.handshake_type == handshake::handshake_type_t::finished) {
										handshake_msgs += hs_msg.build_content_();
										update_key_iv();
										{
											finished finished_msg(*this, handshake_msgs);
											send(finished_msg);
										}
										client_state = client_state_t::connected;
										const auto& cipher = active_cipher();
										master_secret = cipher.HMAC_hash(
												std::string(cipher.digest_length, 0),
												cipher.derive_secret(handshake_secret, "derived", "")
										);
										client_application_traffic_secret = var_unsigned::from_bytes(
												cipher.derive_secret(master_secret, "c ap traffic", handshake_msgs));
										server_application_traffic_secret = var_unsigned::from_bytes(
												cipher.derive_secret(master_secret, "s ap traffic", handshake_msgs));
										update_key_iv();
										break;
									}
									throw alert::unexpected_message();
								default:
									throw alert::unexpected_message();
							}
						}
					}
				});
			} catch (alert& alert) {
				send(alert);
				close();
			}
		}
	}

	bool client::connect(const std::string_view host, const uint16_t port) {
		close();
		reset();
		return client_.connect(host, port) && (handshake(), client_state == client_state_t::connected);
	}

	bool client::connected() const {
		return client_.connected() && (client_state == client_state_t::connected || client_state == client_state_t::wait_closed);
	}

	std::string client::read(std::size_t size) {
		std::string read_data;
		while (read_data.size() < size) {
			char buffer[50];
			if (const auto read = app_data_buffer.readsome(buffer, std::min<std::streamsize>(size - read_data.size(), 50)); read == 0) {
				try {
					record::parse(*this, [&](record& msg){
						auto&& msg_type = typeid(msg);
						if (msg_type == typeid(application_data)) {
							auto& cast_msg = dynamic_cast<application_data&>(msg);
							app_data_buffer << cast_msg.data;
						}
						if (msg_type == typeid(alert)) {
							auto& cast_msg = dynamic_cast<alert&>(msg);
							switch (cast_msg.description) {
								case alert_description_t::close_notify:
									close();
									break;
							}
						}
						if (msg_type == typeid(key_update)) {
							auto& cast_msg = dynamic_cast<key_update&>(msg);
						}
					});
				} catch (const std::exception&) {
					break;
				}
			} else
				read_data.append(buffer, read);
		}
		return read_data;
	}

	std::size_t client::write(std::string_view buffer) {
		application_data data(buffer);
		send(data);
		return buffer.length();
	}

	bool client::finish() {
		client_state = client_state_t::wait_closed;
		auto&& close_alert = alert::close_notify(client_state_t::wait_encrypted_extensions <= client_state);
		send(close_alert);
		return client_.finish();
	}

	void client::close() {
		if (connected())
			finish();
		context::client_.close();
	}

	std::size_t client::available() {
		return app_data_buffer.view().size();
	}

	void client::add_group(key_exchange_manager* ptr) {
		managers.emplace_back(ptr);
	}

	void client::add_group(const std::string_view cipher_suites) {
		for (auto& str: split(cipher_suites, ':'))
			if (auto ptr = get_key_manager(str); ptr)
				managers.emplace_back(ptr);
	}

	void client::mock_group(named_group_t ng) {
		managers.emplace_back(new unimplemented_group(ng));
	}

	void client::set_random(std::string_view bytes) {
		random_random = false;
		std::copy(bytes.begin(), bytes.end(), random);
	}

	void client::add_cipher(cipher_suite* suite) {
		cipher_suites.emplace_back(suite);
	}

	void client::add_cipher(const std::string_view ciphers) {
		for (auto& str: split(ciphers, ':'))
			if (auto ptr = get_cipher_suite(str); ptr)
				cipher_suites.emplace_back(ptr);
	}

	void client::mock_cipher(cipher_suite_t c) {
		cipher_suites.emplace_back(new unimplemented_cipher_suite(c));
	}

	void client::send(record& record) {
		std::cout << "Sending record " << record;
		for (auto& s: record.build(*this))
			client_.write(s);
	}

	void client::add_alpn(std::string_view values) {
		alpn_protocols.merge(split(values, ':'));
	}
}
