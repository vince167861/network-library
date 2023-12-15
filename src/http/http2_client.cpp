#include "http2/client.h"
#include "utils.h"

#include "http2/stream_control.h"

#include <iostream>

namespace leaf::network::http2 {

	bool client::connect(const std::string_view host, const uint16_t port) {
		if (client_.connected()
				&& connected_remote_.value().first == host && connected_remote_.value().second == port)
			return true;
		close();
		if (!client_.connect(host, port))
			return false;
		connected_remote_.emplace(host, port);
		client_.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
		send(settings_frame{pack_settings()});
		const auto first_frame = frame::parse(client_);
		if (!first_frame || first_frame->type != frame_type_t::settings) {
			close(error_t::protocol_error);
			return false;
		}
		process_settings(reinterpret_cast<settings_frame&>(*first_frame).values);
		return true;
	}

	bool client::connected() const {
		return connected_remote_.has_value() && client_.connected();
	}

	void client::close(const error_t error_code, const std::string_view add) {
		if (connected())
			send(go_away_frame{remote_config.last_open_stream, error_code, add});
		client_.close();
		connected_remote_.reset();
	}

	void client::process_settings(const setting_values_t& settings_f) {
		update_remote_config(settings_f);
		send(settings_frame{});
	}

	client::client(network::client& client_)
		: context(endpoint_type_t::client), client_(client_) {
	}

	std::future<response> client::send(const http::request& req) {
		uint16_t port = req.request_url.port;
		if (port == 0) {
			if (req.request_url.scheme == "http")
				port = 80;
			else if (req.request_url.scheme == "https")
				port = 443;
		}
		if (!port)
			throw std::runtime_error("Unknown scheme; assign port explicitly.");
		if (!connect(req.request_url.host, port))
			throw std::runtime_error{"Connect failed."};
		auto& http2_stream = local_open_stream();
		http2_stream.send_request(client_, req);
		return http2_stream.get_future();
	}

	void client::send(const frame& frame) const {
		if (!connected())
			throw std::runtime_error("Client is not connected.");
		if (closing_.has_value()) {
			if (const auto sf = dynamic_cast<const stream_frame*>(&frame); sf && sf->stream_id > closing_.value())
				throw std::runtime_error("Connection is closing.");
		}
		std::cout << "[HTTP/2 Client] Sending " << frame;
		if (const auto s_f = dynamic_cast<const settings_frame*>(&frame)) {
			std::string data;
			for (auto& [s, v]: s_f->values) {
				reverse_write(data, s);
				reverse_write(data, v);
			}
			reverse_write<std::uint32_t>(client_, data.size(), 3);
			reverse_write(client_, frame_type_t::settings);
			reverse_write<uint8_t>(client_, s_f->ack ? 1 : 0);
			reverse_write<uint32_t>(client_, 0);
			client_.write(data);
		} else if (const auto p_f = dynamic_cast<const ping_frame*>(&frame)) {
			reverse_write<uint32_t>(client_, 8, 3);
			reverse_write(client_, frame_type_t::ping);
			reverse_write<uint8_t>(client_, p_f->ack ? 1 : 0);
			reverse_write<uint32_t>(client_, 0);
			reverse_write(client_, p_f->data);
		} else if (const auto g_f = dynamic_cast<const go_away_frame*>(&frame)) {
			reverse_write(client_, 8 + g_f->additional_data.length(), 3);
			reverse_write(client_, frame_type_t::go_away);
			reverse_write<uint8_t>(client_, 0);
			reverse_write<uint32_t>(client_, 0);
			reverse_write(client_, g_f->last_stream_id);
			reverse_write(client_, g_f->error_code);
			client_.write(g_f->additional_data);
		} else
			throw std::runtime_error{"Unimplemented frame send."};
	}

	void client::process() {
		while (client_.connected() && (!process_tasks() || has_pending_streams())) {
			auto frame = frame::parse(client_);
			std::cout << "[HTTP/2 Client] Received " << *frame;
			if (const auto wu = std::dynamic_pointer_cast<window_update_frame>(frame);
					wu && wu->stream_id == 0) {
				remote_config.current_window_bytes += wu->window_size_increment;
			} else if (const auto s_f = std::dynamic_pointer_cast<stream_frame>(frame))
				get_stream(s_f->stream_id).handle(*s_f);
			else {
				switch (frame->type) {
					case frame_type_t::settings: {
						if (auto& settings_f = reinterpret_cast<settings_frame&>(*frame); !settings_f.ack)
							process_settings(settings_f.values);
						break;
					}
					case frame_type_t::go_away: {
						auto& ga_f = reinterpret_cast<go_away_frame&>(*frame);
						closing_ = ga_f.last_stream_id;
						remote_closing(ga_f.last_stream_id);
						break;
					}
					case frame_type_t::ping: {
						break;
					}
					default:
						break;
				}
			}
		}
	}

	client::~client() {
		close();
	}

	stream_error::stream_error(const error_t err)
		: code(err) {
	}

}
