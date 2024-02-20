#include "tls/endpoint.h"
#include "tls-record/record.h"
#include "tls-record/alert.h"
#include "tls-record/handshake.h"
#include "utils.h"
#include <iostream>

namespace leaf::network::tls {

	endpoint::endpoint(network::endpoint& __u, const endpoint_type_t __t, std::unique_ptr<random_number_generator> __g)
			: underlying_(__u), secret_(__t, cipher_), random_(std::move(__g)) {
	}

	byte_string endpoint::read(const std::size_t size) {
		byte_string read_data;
		while (read_data.size() < size) {
			const auto stored = app_data_.read(size - read_data.size());
			if (stored.size() == 0) {
				const auto record = record::extract(underlying_, secret_);
				switch (record.type) {
					case content_type_t::alert:
						switch (alert alert{record.messages}; alert.description) {
							case alert_description_t::close_notify:
								close();
								break;
							default:
								std::cout << std::format("[TLS client] got {}: {}\n", alert.level, alert.description);
								break;
						}
						break;
					case content_type_t::application_data:
						app_data_.append(record.messages);
						break;
					case content_type_t::handshake: {
						byte_string_view __content = record.messages;
						const auto __presult = parse_handshake(__content, record.encrypted(), true);
						if (!__presult)
							break;
						auto& __msg = __presult.value();
						std::cout << std::format("[TLS endpoint] got {}\n", __msg);
						if (std::holds_alternative<new_session_ticket>(__msg)) {
							auto& peer_new_session_ticket = std::get<new_session_ticket>(__msg);
						} else if (std::holds_alternative<key_update>(__msg)) {
							auto& __r_key_update = std::get<key_update>(__msg);
							switch (__r_key_update.request_update) {
								case key_update::key_update_request::update_requested: {
									send_(content_type_t::handshake, true, {std::make_unique<key_update>(false)});
									secret_.update_application_key();
									break;
								}
								case key_update::key_update_request::update_not_requested:
									break;
								default:
									throw alert::unexpected_message();
							}
						}
						break;
					}
					default:
						throw std::runtime_error{"unexpected"};
				}
			} else
				read_data.append(stored);
		}
		return read_data;
	}

	void endpoint::write(const byte_string_view buffer) {
		record record{content_type_t::application_data, secret_};
		record.messages = buffer;
		send_(record);
	}

	void endpoint::use_group(const named_group_t ng) {
		key_exchange_ = get_key_manager(ng, *random_);
	}

	void endpoint::use_group(std::unique_ptr<key_exchange_manager> mgr) {
		key_exchange_ = std::move(mgr);
	}

	void endpoint::use_cipher(const cipher_suite_t c) {
		if (cipher_ && cipher_->value != c)
			throw alert::illegal_parameter();
		cipher_ = get_cipher_suite(c);
	}

	void endpoint::finish() {
		auto close_alert = alert::close_notify();
		send_(record::construct(content_type_t::alert, std::nullopt, close_alert));
		underlying_.finish();
	}

	void endpoint::close() {
		if (connected())
			finish();
		underlying_.close();
	}

	void endpoint::send_(const record& record) {
		std::cout << std::format("[TLS endpoint] sending {}\n", record);
		underlying_.write(static_cast<byte_string>(record));
	}

	void endpoint::send_(content_type_t type, bool encrypted, std::initializer_list<std::unique_ptr<message>> msgs) {
		record record{type, encrypted ? std::optional{std::ref(secret_)} : std::nullopt};
		for (auto& __m: msgs) {
			std::cout << std::format("[TLS endpoint] sending {}\n", *__m);
			record.messages += *__m;
		}
		underlying_.write(static_cast<byte_string>(record));
	}

	std::uint8_t endpoint::read() {
		const auto data = read(1);
		if (data.empty())
			throw std::runtime_error{"read failed"};
		return data[0];
	}

	void endpoint::write(const std::uint8_t octet) {
		write({&octet, 1});
	}
}
