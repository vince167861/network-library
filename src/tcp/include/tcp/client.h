#pragma once
#include "tcp/endpoint.h"

namespace leaf::network::tcp {

	struct client final: endpoint, network::client {

		void connect(const std::string_view host, const tcp_port_t port) override {
			close();
			addrinfo
					__hint{.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP},
					* __result = nullptr;
			if (const std::string host_copy(host);
					getaddrinfo(host_copy.c_str(), std::to_string(port).c_str(), &__hint, &__result))
				handle_error_("getaddrinfo");
			for (auto ptr = __result; ptr; ptr = ptr->ai_next) {
				socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (socket_ == invalid_socket)
					continue;
				if (const int result = ::connect(socket_, ptr->ai_addr, ptr->ai_addrlen); result) {
					close();
					continue;
				}
				break;
			}
			freeaddrinfo(__result);
			if (socket_ == invalid_socket)
				throw std::runtime_error(std::format("{}:{} is unreachable", host, port));
		}

		std::size_t available() override {
			unsigned long avail = 0;
			if (const auto result = ioctl(socket_, FIONREAD, &avail); result < 0)
				handle_error_("ioctl(FIONREAD)");
			return avail;
		}
	};
}
