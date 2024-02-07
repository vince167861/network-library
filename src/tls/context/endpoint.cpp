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

	std::string endpoint::read(const std::size_t size) {
		std::string read_data;
		while (read_data.size() < size) {
			char buffer[1024];
			const auto read
					= app_data_buffer.readsome(buffer, std::min<std::streamsize>(size - read_data.size(), 1024));
			if (read == 0) {
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
						app_data_buffer << record.messages;
						break;
					case content_type_t::handshake: {
						std::string_view handshake_fragments = record.messages;
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
				read_data.append(buffer, read);
		}
		return read_data;
	}

	std::size_t endpoint::write(const std::string_view buffer) {
		record record{content_type_t::application_data, cipher_};
		record.messages = buffer;
		send_(record);
		return buffer.length();
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
		underlying.write(record.to_bytestring());
	}

	void endpoint::send_(content_type_t type, bool encrypted, std::initializer_list<std::unique_ptr<message>> msgs) {
		record record{type, encrypted ? std::optional{std::ref(cipher_)} : std::nullopt};
		for (auto& ptr: msgs) {
			std::cout << std::format("[TLS endpoint] sending {}\n", *ptr);
			record.messages += ptr->to_bytestring();
		}
		underlying.write(record.to_bytestring());
	}
}
