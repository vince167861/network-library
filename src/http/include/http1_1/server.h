#pragma once
#include "stream_endpoint.h"
#include "http/message.h"
#include <expected>

namespace network::http {

	struct serverside_endpoint;

	struct server final: basic_server {

		explicit server(stream_server& __b, const bool secured)
			: base_(__b), secured_(secured) {
		}

		void listen(tcp_port_t, std::size_t max_connection) override;

		void close() override {
			base_.close();
		}

		std::unique_ptr<serverside_endpoint> accept();

	private:
		stream_server& base_;

		const bool secured_;
	};

	enum class request_parse_error {
		invalid_line_folding, request_line_missing_space, invalid_request_target, invalid_header_fields,
		message_content_error
	};

	struct serverside_endpoint final: basic_endpoint {

		explicit serverside_endpoint(std::unique_ptr<stream_endpoint> __b)
			: base_(std::move(__b)) {
		}

		std::expected<request, request_parse_error> fetch();

		void send(const response&);

		[[nodiscard]] bool connected() const override {
			return base_->connected();
		}

		void finish() override {
			base_->finish();
		}

		void close() override {
			base_->close();
		}

		stream_endpoint& base() const {
			return *base_;
		}

	private:
		const std::unique_ptr<stream_endpoint> base_;

		void send_error_(request_parse_error);

		void send_as_html_(status, std::string_view);
	};
}
