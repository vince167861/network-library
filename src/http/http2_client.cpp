#include "http2/client.h"

#include <iostream>

namespace leaf::network::http2 {

	bool client::connect(const std::string_view host, const uint16_t port) {
		if (client_.connected() && connected_remote_.value().first == host && connected_remote_.value().second == port)
			return true;
		close();
		if (!client_.connect(host, port))
			return false;
		client_.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
		send(settings_frame{pack_settings()});
		const auto first_frame = frame::parse(client_);
		if (!first_frame || first_frame->type != frame_type_t::settings) {
			close(error_t::protocol_error);
			return false;
		}
		process_settings(reinterpret_cast<settings_frame&>(*first_frame).values);
		connected_remote_.emplace(host, port);
		return true;
	}

	void client::close(const error_t error_code, const std::string_view add) {
		send(go_away_frame{remote_config.last_open_stream, error_code, add});
		client_.close();
		connected_remote_.reset();
	}

	void client::process_settings(const std::list<std::pair<settings_t, uint32_t>>& settings_f) {
		update_remote_config(settings_f);
		send(settings_frame{});
	}

	client::client(network::client& client_)
		: context(endpoint_type_t::client), client_(client_) {
	}

	std::future<response> client::send(const request& req) {
		std::pair tuple{response{req}, std::promise<response>{}};
		auto& promise = tuple.second;
		auto future = promise.get_future();

		uint16_t port = req.request_url.port;
		if (port == 0) {
			if (req.request_url.scheme == "http")
				port = 80;
			else if (req.request_url.scheme == "https")
				port = 443;
		}
		if (port && connect(req.request_url.host, port)) {
			auto stream_id = new_local_stream_id();
			for (const auto& f: req.build(stream_id, local_packer, remote_config.max_frame_size))
				if (!send(*f))
					promise.set_exception(std::make_exception_ptr(std::exception{})); // TODO: Use custom exception
			pending_requests_.emplace(stream_id, std::move(tuple));
		} else
			promise.set_exception(std::make_exception_ptr(std::exception{})); // TODO: Use custom exception
		return future;
	}

	bool client::send(const frame& frame) const {
		if (!connected_remote_.has_value() || !client_.connected())
			return false;
		if (closing_.has_value()) {
			if (const auto sf = dynamic_cast<const stream_frame*>(&frame); sf && sf->stream_id > closing_.value())
				return false;
		}
		std::cout << "[HTTP/2 Client] Sending frame " << frame;
		frame.send(client_);
		return true;
	}

	void client::process() {
		while (client_.connected() && !pending_requests_.empty()) {
			auto frame = frame::parse(client_);
			std::cout << "[HTTP/2 Client] Received frame " << *frame;
			switch (frame->type) {
				case frame_type_t::settings: {
					if (auto& settings_f = reinterpret_cast<settings_frame&>(*frame); !settings_f.ack)
						process_settings(settings_f.values);
					break;
				}
				case frame_type_t::continuation:
				case frame_type_t::headers: {
					auto& headers_info_f = reinterpret_cast<headers_info_frame&>(*frame);
					auto& [response, promise]
							= pending_requests_.at(headers_info_f.stream_id);
					response.pending_field_block_fragments += headers_info_f.field_block_fragments;
					if (frame->type == frame_type_t::headers)
						response.header_only = reinterpret_cast<headers_frame&>(headers_info_f).end_stream;
					if (headers_info_f.end_headers) {
						for (auto& [name, value]: remote_packer.decode(response.pending_field_block_fragments)) {
							if (name == ":status")
								response.status = std::stol(value);
							else
								response.headers.emplace_back(name, value);
						}
						response.pending_field_block_fragments.clear();
						if (response.header_only) {
							promise.set_value(std::move(response));
							pending_requests_.erase(headers_info_f.stream_id);
							// todo: send end stream
						}
					}
					break;
				}
				case frame_type_t::data: {
					auto& data_f = reinterpret_cast<data_frame&>(*frame);
					auto& [response, promise] = pending_requests_.at(data_f.stream_id);
					response.body += data_f.data;
					if (data_f.end_stream) {
						promise.set_value(std::move(response));
						pending_requests_.erase(data_f.stream_id);
						// todo: send end stream
					}
					break;
				}
				case frame_type_t::rst_stream: {
					auto& rst_f = reinterpret_cast<rst_stream&>(*frame);
					auto& promise = pending_requests_.at(rst_f.stream_id).second;
					promise.set_exception(std::make_exception_ptr(stream_error{rst_f.error_code}));
					pending_requests_.erase(rst_f.stream_id);
					break;
				}
				case frame_type_t::push_promise: {
					auto& pp_f = reinterpret_cast<push_promise_frame&>(*frame);
					std::pair tuple{response{{}}, std::promise<response>{}};
					new_remote_stream_id(pp_f.promised_stream_id);
					pending_requests_.at(pp_f.stream_id).first.pushed.emplace_back(tuple.second.get_future());
					pending_requests_.emplace(pp_f.promised_stream_id, std::move(tuple));
				}
				case frame_type_t::go_away: {
					auto& ga_f = reinterpret_cast<go_away_frame&>(*frame);
					closing_ = ga_f.last_stream_id;
					for (auto ptr = pending_requests_.begin(); ptr != pending_requests_.end();) {
						const auto current = ptr++;
						if (current->first > ga_f.last_stream_id) {
							// TODO: Use custom exception
							current->second.second.set_exception(std::make_exception_ptr(std::exception{}));
							pending_requests_.erase(current);
						}
					}
				}
				default:
					break;
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
