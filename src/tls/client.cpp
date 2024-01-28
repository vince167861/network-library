#include "tls/client.h"

#include "tls-context/context.h"
#include "tls-record/alert.h"
#include "tls-record/record.h"
#include "tls-extension/extension.h"

#include "utils.h"
#include <utility>
#include <iostream>

namespace leaf::network::tls {

	client::client(network::client& client, std::unique_ptr<random_number_generator> generator)
		: context(protocol_version_t::TLS1_3, client, endpoint_type_t::client), random_generator(std::move(generator)) {
	}

	void client::reset() {
		if (random_random)
			for (auto& i : random)
				i = random_generator->unit();
		if (init_session_id)
			session_id = init_session_id.value();
		else if (compatibility_mode)
			session_id = random_generator->number(32).to_bytestring(std::endian::big);
		else
			session_id.clear();
	}

	client_hello client::gen_client_hello() const {
		client_hello ch(*this);
		if (server_name)
			ch.extensions.push_back(tls::server_name{{server_name::name_type_t::host_name, server_name.value()}});
		ch.extensions.push_back(supported_groups{*this});
		ch.extensions.push_back(key_share{*this});
		ch.extensions.push_back(supported_versions{*this});
		ch.extensions.push_back(signature_algorithms{
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
		ch.extensions.push_back(psk_key_exchange_modes{psk_key_exchange_mode_t::psk_dhe_ke});
		ch.extensions.push_back(record_size_limit{16385});
		if (!alpn_protocols.empty())
			ch.extensions.push_back(alpn{alpn_protocols});
		std::copy_n(random, 32, ch.random);
		ch.legacy_session_id = session_id;
		return ch;
	}

	void client::handshake() {
		auto ch = gen_client_hello();
		send(record::construct(content_type_t::handshake, false, {ch}, *this));
		client_state = client_state_t::wait_server_hello;

		auto handshake_msgs = ch.to_bytestring();
		std::string early_secret, handshake_secret, master_secret, cert_verify;
		while (client_state != client_state_t::connected && client_state != client_state_t::closed) {
			auto record = record::extract(*this);
			std::cout << std::format("[TLS1.3 client] Received {}\n", record);
			try {
				switch (record.type) {
					case content_type_t::handshake:
						for (std::string_view handshake_fragments{record.messages}; !handshake_fragments.empty(); ) {
							const auto opt_message = parse_handshake(*this, handshake_fragments, record.encrypted);
							if (!opt_message)
								break;
							auto& handshake_msg = opt_message.value();
							switch (client_state) {
								case client_state_t::wait_server_hello: {
									if (!std::holds_alternative<server_hello>(handshake_msg))
										throw alert::unexpected_message();
									auto& srv_hello = std::get<server_hello>(handshake_msg);
									use_cipher(srv_hello.cipher_suite);
									if (srv_hello.is_hello_retry_request)
										handshake_msgs = message_hash(active_cipher(), handshake_msgs);
									handshake_msgs += srv_hello.to_bytestring();
									if (srv_hello.is_hello_retry_request) {
										for (auto& ext: srv_hello.extensions) {
											if (ext.type == ext_type_t::key_share) {
												auto [group, key]
													= key_share{ext.data, true, *this}.shares.front();
												use_group(group);
												active_manager().generate_private_key(*random_generator);
											}
										}
										auto ch2 = gen_client_hello();
										send(record::construct(content_type_t::handshake, false, ch2, *this));
										handshake_msgs += ch2.to_bytestring();
									} else {
										const auto& cipher = active_cipher();
										early_secret = cipher.HMAC_hash(
											pre_shared_key.empty()
												? std::string(cipher.digest_length, 0)
												: pre_shared_key,
											""); // todo: should calculate before wait_server_hello?
										for (auto& ext: srv_hello.extensions) {
											if (ext.type == ext_type_t::key_share) {
												auto [group, key]
													= key_share{ext.data, false, *this}.shares.front();
												use_group(group);
												active_manager().exchange_key(key);
											}
										}
										client_state = client_state_t::wait_encrypted_extensions;
										handshake_secret = cipher.HMAC_hash(active_manager().shared_key(),
											cipher.derive_secret(early_secret, "derived", ""));
										client_handshake_traffic_secret = var_unsigned::from_bytes(
											cipher.derive_secret(handshake_secret, "c hs traffic", handshake_msgs));
										server_handshake_traffic_secret = var_unsigned::from_bytes(
											cipher.derive_secret(handshake_secret, "s hs traffic", handshake_msgs));
										update_key_iv();
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
									update_key_iv();
									send(record::construct(content_type_t::handshake,
										true, finished{*this, handshake_msgs}, *this));
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
								default:
									throw alert::unexpected_message();
							}
						}
						break;
					case content_type_t::change_cipher_spec:
						break;
					case content_type_t::alert: {
						alert alert{record.messages};
						std::cout << std::format("[TLS1.3 client] got {}: {}\n", alert.level, alert.description);
						[[fallthrough]];
					}
					default:
						throw alert::unexpected_message();
				}
			} catch (alert& alert) {
				send(record::construct(content_type_t::alert, false, {alert}, *this));
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

	std::string client::read(const std::size_t size) {
		std::string read_data;
		while (read_data.size() < size) {
			char buffer[50];
			if (const auto read = app_data_buffer.readsome(buffer, std::min<std::streamsize>(size - read_data.size(), 50)); read == 0) {
				try {
					auto record = record::extract(*this);
					switch (record.type) {
						case content_type_t::alert:
							switch (alert{record.messages}.description) {
								case alert_description_t::close_notify:
									close();
									break;
								default:
									break;
							}
							break;
						case content_type_t::application_data:
							app_data_buffer << record.messages;
							break;
					}
				} catch (...) {
					break;
				}
			} else
				read_data.append(buffer, read);
		}
		return read_data;
	}

	std::size_t client::write(const std::string_view buffer) {
		record record{content_type_t::application_data, true, *this};
		record.messages = buffer;
		send(record);
		return buffer.length();
	}

	bool client::finish() {
		client_state = client_state_t::wait_closed;
		auto close_alert = alert::close_notify();
		send(record::construct(content_type_t::alert, false, {close_alert}, *this));
		return client_.finish();
	}

	void client::close() {
		if (connected())
			finish();
		client_.close();
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
		std::ranges::copy(bytes, random);
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

	void client::send(const record& record) const {
		std::cout << std::format("[TLS1.3 client] Sending {}\n", record);
		client_.write(record.to_bytestring());
	}

	void client::add_alpn(const std::string_view values) {
		alpn_protocols.merge(split(values, ':'));
	}
}
