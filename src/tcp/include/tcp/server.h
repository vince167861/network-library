#pragma once
#include "tcp/endpoint.h"

namespace network::tcp {

	class server final: public stream_server {

		socket_t socket_{invalid_socket};

		[[noreturn]] void handle_error_(std::string_view function) {
			switch (const int error_no = last_error) {
				case error_conn_aborted:
					throw std::runtime_error("tcp closed");
				case error_conn_reset:
					throw std::runtime_error{"Connection reset."};
				case error_conn_refused:
					throw std::runtime_error{"Connection refused."};
				default:
					throw std::runtime_error{std::format("{} gives error {}", function, error_no)};
			}
		}

	public:
		server() {
#ifdef PLATFORM_Windows
			wsa_control::acquire();
#endif
		}

		void listen(std::uint16_t port, std::size_t max_connection) override {
			addrinfo hint{
					.ai_flags = AI_PASSIVE, .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP},
					* result_addr = nullptr;
			if (getaddrinfo(nullptr, std::to_string(port).c_str(), &hint, &result_addr))
				handle_error_(std::format("getaddrinfo(null, {})", port));
			for (auto ptr = result_addr; ptr; ptr = ptr->ai_next) {
				socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (socket_ == invalid_socket)
					continue;
				if (const int result = ::bind(socket_, ptr->ai_addr, ptr->ai_addrlen); result) {
					close();
					continue;
				}
				break;
			}
			freeaddrinfo(result_addr);
			if (socket_ == invalid_socket)
				handle_error_("socket() or bind()");
			if (::listen(socket_, static_cast<int>(max_connection)))
				handle_error_("listen()");
		}

		std::unique_ptr<stream_endpoint> accept() override {
			const socket_t socket = ::accept(socket_, nullptr, nullptr);
			if (socket == invalid_socket)
				handle_error_("accept()");
			return std::make_unique<tcp::endpoint>(socket);
		}

		void close() override {
			::closesocket(socket_);
			socket_ = invalid_socket;
		}

		~server() {
			::closesocket(socket_);
#ifdef PLATFORM_Windows
			wsa_control::release();
#endif
		}
	};
}
