#include "http2/client.h"
#include "http2/stream.h"
#include "utils.h"

#include <iostream>
#include <format>

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
		write_(settings_frame{pack_settings()});
		const auto first_frame = parse_frame(client_);
		if (!std::holds_alternative<settings_frame>(first_frame)) {
			close(error_t::protocol_error);
			return false;
		}
		process_settings(std::get<settings_frame>(first_frame).values);
		return true;
	}

	bool client::connected() const {
		return connected_remote_.has_value() && client_.connected();
	}

	void client::close(const error_t error_code, const std::string_view add) {
		if (connected())
			write_(go_away{remote_config.last_open_stream, error_code, add});
		client_.close();
		connected_remote_.reset();
	}

	void client::process_settings(const setting_values_t& settings_f) {
		update_remote_config(settings_f);
		write_(settings_frame{});
	}

	client::client(network::client& client_)
		: context(endpoint_type_t::client), client_(client_) {
	}

	std::future<http::response> client::fetch(const http::request& req) {
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
		auto http2_stream = std::make_unique<response_handler>(client_, *this, req);
		auto future = http2_stream->get_future();
		register_handler(std::move(http2_stream));
		return future;
	}

	http::event_source client::stream(const http::request& request) {
		uint16_t port = request.request_url.port;
		if (port == 0) {
			if (request.request_url.scheme == "http")
				port = 80;
			else if (request.request_url.scheme == "https")
				port = 443;
		}
		if (!port)
			throw std::runtime_error("Unknown scheme; assign port explicitly.");
		if (!connect(request.request_url.host, port))
			throw std::runtime_error{"Connect failed."};
		auto http2_stream = std::make_unique<event_stream_handler>(*this, request);
		auto source = http2_stream->get_event_source(client_);
		register_handler(std::move(http2_stream));
		return source;
	}

	void client::write_(const frame& frame) const {
		if (!connected())
			throw std::runtime_error("Client is not connected.");
		std::cout << std::format("[HTTP/2 client] Sending {}\n", frame);
		if (std::holds_alternative<settings_frame>(frame)) {
			auto& casted = std::get<settings_frame>(frame);
			std::string data;
			for (auto& [s, v]: casted.values) {
				write(std::endian::big, data, s);
				write(std::endian::big, data, v);
			}
			write(std::endian::big, client_, data.size(), 3);
			write(std::endian::big, client_, frame_type_t::settings);
			write(std::endian::big, client_, casted.ack ? 1 : 0, 1);
			write(std::endian::big, client_, 0, 4);
			client_.write(data);
			return;
		}
		if (std::holds_alternative<ping_frame>(frame)) {
			auto& casted = std::get<ping_frame>(frame);
			write(std::endian::big, client_, 8, 3);
			write(std::endian::big, client_, frame_type_t::ping);
			write(std::endian::big, client_, casted.ack ? 1 : 0, 1);
			write(std::endian::big, client_, 0, 4);
			write(std::endian::big, client_, casted.data);
			return;
		}
		if (std::holds_alternative<go_away>(frame)) {
			auto& casted = std::get<go_away>(frame);
			write(std::endian::big, client_, 8 + casted.additional_data.length(), 3);
			write(std::endian::big, client_, frame_type_t::go_away);
			write(std::endian::big, client_, 0, 1);
			write(std::endian::big, client_, 0, 4);
			write(std::endian::big, client_, casted.last_stream_id);
			write(std::endian::big, client_, casted.error_code);
			client_.write(casted.additional_data);
			return;
		}
		throw std::runtime_error{"Unimplemented frame write_to_."};
	}

	void client::process() {
		while (client_.connected() && (!process_tasks() || has_pending_streams())) {
			auto frame = parse_frame(client_);
			std::cout << std::format("[HTTP/2 client] Received {}\n", frame);
			if (std::holds_alternative<window_update_frame>(frame)) {
				const auto& casted = std::get<window_update_frame>(frame);
				if (const auto stream_id = casted.stream_id)
					get_stream(stream_id).increase_window(casted.window_size_increment);
				else
					remote_config.current_window_bytes += casted.window_size_increment;
			} else if (std::holds_alternative<settings_frame>(frame)) {
				auto& casted = std::get<settings_frame>(frame);
				if (!casted.ack)
					process_settings(casted.values);
			} else if (std::holds_alternative<go_away>(frame)) {
				auto& casted = std::get<go_away>(frame);
				closing_ = casted.last_stream_id;
				remote_closing(casted.last_stream_id);
			} else if (std::holds_alternative<ping_frame>(frame)) {
				auto& casted = std::get<ping_frame>(frame);
				ping_frame ack;
				ack.ack = true;
				ack.data = casted.data;
				write_(ack);
			} else if (std::holds_alternative<headers_frame>(frame)) {
				auto& casted = std::get<headers_frame>(frame);
				get_stream(casted.stream_id).notify(casted.get_headers(remote_packer), casted.end_stream);
			} else if (std::holds_alternative<push_promise_frame>(frame)) {
				auto& casted = std::get<push_promise_frame>(frame);
				get_stream(casted.stream_id).reserve(casted.promised_stream_id, casted.get_headers(remote_packer));
			} else if (std::holds_alternative<data_frame>(frame)) {
				auto& casted = std::get<data_frame>(frame);
				get_stream(casted.stream_id).notify(casted.data, casted.end_stream);
			} else if (std::holds_alternative<rst_stream>(frame)) {
				auto& casted = std::get<rst_stream>(frame);
				get_stream(casted.stream_id).reset();
			}
		}
	}

	client::~client() {
		close();
	}
}
