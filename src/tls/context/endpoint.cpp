#include "tls-context/endpoint.h"
#include "tls-record/record.h"
#include "tls-record/alert.h"
#include "tls-record/handshake.h"
#include "utils.h"
#include <iostream>

namespace leaf::network::tls {

	endpoint::endpoint(network::endpoint& endpoint, const endpoint_type_t t, std::unique_ptr<random_number_generator> generator)
			: underlying(endpoint), random_generator(std::move(generator)), cipher_(t, active_cipher_) {
	}

	byte_string endpoint::read(const std::size_t size) {
		byte_string read_data;
		while (read_data.size() < size) {
			const auto stored = app_data_buffer.read(size - read_data.size());
			if (stored.size() == 0) {
				const auto record = record::extract(underlying, cipher_);
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
						app_data_buffer.append(record.messages);
						break;
					case content_type_t::handshake: {
						byte_string_view handshake_fragments = record.messages;
						const auto opt_message = parse_handshake(*this, handshake_fragments, record.encrypted(), true);
						if (!opt_message)
							break;
						auto& handshake_msg = opt_message.value();
						if (std::holds_alternative<new_session_ticket>(handshake_msg)) {
							auto& peer_new_session_ticket = std::get<new_session_ticket>(handshake_msg);
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
		record record{content_type_t::application_data, cipher_};
		record.messages = buffer;
		send_(record);
	}

	void endpoint::use_group(const named_group_t ng) {
		active_manager_ = get_key_manager(ng, *random_generator);
	}

	void endpoint::use_group(std::unique_ptr<key_exchange_manager> mgr) {
		active_manager_ = std::move(mgr);
	}

	void endpoint::use_cipher(const cipher_suite_t c) {
		if (active_cipher_ && active_cipher_->value != c)
			throw alert::illegal_parameter();
		active_cipher_ = get_cipher_suite(c);
	}

	void endpoint::finish() {
		auto close_alert = alert::close_notify();
		send_(record::construct(content_type_t::alert, std::nullopt, close_alert));
		underlying.finish();
	}

	void endpoint::close() {
		if (connected())
			finish();
		underlying.close();
	}

	void endpoint::send_(const record& record) {
		std::cout << std::format("[TLS endpoint] sending {}\n", record);
		underlying.write(static_cast<byte_string>(record));
	}

	void endpoint::send_(content_type_t type, bool encrypted, std::initializer_list<std::unique_ptr<message>> msgs) {
		record record{type, encrypted ? std::optional{std::ref(cipher_)} : std::nullopt};
		for (auto& __m: msgs) {
			std::cout << std::format("[TLS endpoint] sending {}\n", *__m);
			record.messages += *__m;
		}
		underlying.write(static_cast<byte_string>(record));
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
