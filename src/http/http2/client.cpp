#include "http2/client.h"
#include "internal/utils.h"
#include <iostream>
#include <format>

namespace leaf::network::http2 {

	constexpr std::uint8_t preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

	client::client(network::client& client_)
		: state_(connection_state::endpoint_type_t::client, client_), client_(client_) {
	}

	void client::connect(const std::string_view host, const tcp_port_t port) {
		if (client_.connected()
				&& connected_remote_.value().first == host && connected_remote_.value().second == port)
			return;
		close();
		if (!client_.connect(host, port))
			throw std::runtime_error(std::format("cannot connect to {}:{}", host, port));
		connected_remote_.emplace(host, port);
		client_.write(preface);
		state_.write(settings(state_.pack_local_settings()));
		const auto parse_result = parse_frame(client_);
		if (!parse_result)
			throw connection_error(error_t::protocol_error, "first frame must be SETTINGS");
		auto& [__t, __f] = parse_result.value();
		std::cout << std::format("[HTTP/2 client] got {}\n", *__f);
		if (__t != frame_type_t::settings)
			throw connection_error(error_t::protocol_error, "first frame must be SETTINGS");
		process_settings(reinterpret_cast<settings&>(*__f).values);
	}

	bool client::connected() const {
		return connected_remote_.has_value() && client_.connected();
	}

	void client::close(const error_t __c, const std::string_view __a) {
		if (connected())
			state_.write(go_away(state_.remote_config.last_open_stream, __c, __a));
		client_.close();
		connected_remote_.reset();
	}

	void client::process_settings(const setting_values_t& settings_f) {
		state_.update_remote_settings(settings_f);
		state_.write(settings());
	}

	std::future<http::response> client::fetch(http::request req) {
		auto port = req.target.port;
		if (port == 0) {
			if (req.target.scheme == "http")
				port = 80;
			else if (req.target.scheme == "https")
				port = 443;
		}
		if (!port)
			throw std::runtime_error("unknown scheme; assign port explicitly.");
		connect(req.target.host, port);
		return state_.local_open(std::move(req));
	}

	void client::process() {
		while (client_.connected()) {
			const auto __pt = !state_.task_process();
			const bool __ps = state_.has_pending_streams();
			if (__ps) {
				auto parse_result = parse_frame(client_);
				if (!parse_result) {
					if (parse_result.error() != frame_parsing_error::unknown_frame)
						throw connection_error(error_t::internal_error, "frame parsing error");
				} else {
					auto& [__t, __frame] = parse_result.value();
					std::cout << std::format("[HTTP/2 client] got {}\n", *__frame);
					switch (__t) {
						case frame_type_t::window_update:
							if (const auto& __c = dynamic_cast<window_update&>(*__frame); __c.stream_id)
								state_[__c.stream_id].increase_window(__c.window_size_increment);
							else
								state_.remote_config.current_window_bytes += __c.window_size_increment;
							break;
						case frame_type_t::settings:
							if (const auto& __c = reinterpret_cast<settings&>(*__frame); !__c.ack)
								process_settings(__c.values);
							break;
						case frame_type_t::go_away:
							state_.remote_close(reinterpret_cast<go_away&>(*__frame).last_stream_id);
							break;
						case frame_type_t::ping:
							state_.write(ping(true, reinterpret_cast<ping&>(*__frame).data));
							break;
						case frame_type_t::headers: {
							const auto& __c = reinterpret_cast<headers&>(*__frame);
							state_[__c.stream_id].notify(__c.get_headers(state_.remote_packer), __c.end_stream);
							break;
						}
						case frame_type_t::push_promise: {
							const auto& __c = reinterpret_cast<push_promise&>(*__frame);
							auto h = __c.get_headers(state_.remote_packer);
							auto f = state_.remote_reserve(__c.promised_stream_id, h);
							http::request req;
							std::string _url;
							if (const auto n = h.extract(":scheme"))
								_url += n.mapped();
							if (const auto n = h.extract(":authority"))
								_url += "://" + n.mapped();
							if (const auto n = h.extract(":path"))
								_url += n.mapped();
							if (const auto n = h.extract(":method"))
								req.method = n.mapped();
							req.target = {_url};
							req.headers = std::move(h);
							pushed_.emplace(std::move(req), std::move(f));
							break;
						}
						case frame_type_t::data: {
							const auto& __c = reinterpret_cast<data&>(*__frame);
							state_[__c.stream_id].notify(__c.content, __c.end_stream);
							break;
						}
						case frame_type_t::rst_stream: {
							const auto& __c = dynamic_cast<rst_stream&>(*__frame);
							state_[__c.stream_id].remote_reset(__c.error_code);
							break;
						}
						default:
							throw std::runtime_error("unexpected");
					}
				}
			}
			if (!__ps && !__pt)
				close();
		}
	}

	client::~client() {
		close();
	}
}
