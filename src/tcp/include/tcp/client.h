#pragma once

#include "tcp/endpoint.h"

namespace leaf::network::tcp {

	class client final: public endpoint, public network::client {
	public:
		bool connect(std::string_view host, std::uint16_t port) override {
			close();
			addrinfo
					addr_hint{.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP},
					* result_addr = nullptr;
			if (const std::string host_copy(host);
					getaddrinfo(host_copy.c_str(), std::to_string(port).c_str(), &addr_hint, &result_addr))
				handle_error_("getaddrinfo");
			for (auto ptr = result_addr; ptr; ptr = ptr->ai_next) {
				socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (socket_ == invalid_socket)
					continue;
				if (const int result = ::connect(socket_, ptr->ai_addr, ptr->ai_addrlen); result) {
					close();
					continue;
				}
				break;
			}
			freeaddrinfo(result_addr);
			return socket_ != invalid_socket;
		}

		std::size_t available() override {
			unsigned long avail = 0;
			if (const auto result = ioctl(socket_, FIONREAD, &avail); result < 0)
				handle_error_("ioctl(FIONREAD)");
			return avail;
		}
	};
}
