#include "tcp/windows_tcp.h"

namespace leaf::network::tcp {

	client::client() {
		WSAData data;
		if (WSAStartup(MAKEWORD(2, 2), &data))
			throw_error("WSAStartup(MAKEWORD(2, 2), .)");
	}

	void client::throw_error(std::string_view function) {
		std::string desc;
		const auto error = WSAGetLastError();
		switch (error) {
			case WSAECONNABORTED: desc = "connection abort"; break;
		}
		throw api_failed{function, error, desc};
	}

	bool client::connect(std::string_view host, uint16_t port) {
		addrinfo addr_hint { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP };
		addrinfo* result_addr = nullptr;
		{
			const std::string host_copy(host);
			const auto port_string = std::to_string(port);

			if (const int result = getaddrinfo(host_copy.c_str(), port_string.c_str(), &addr_hint, &result_addr); result)
				throw_error("getaddrinfo");
		}

		for (auto ptr = result_addr; ptr; ptr = ptr->ai_next) {
			socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			if (socket_ == INVALID_SOCKET)
				continue;
			if (const int result = ::connect(socket_, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)); result) {
				close();
				continue;
			}
			break;
		}
		freeaddrinfo(result_addr);
		return connected_ = socket_ != INVALID_SOCKET;
	}

	bool client::connected() const {
		return connected_;
	}

	std::string client::read(std::size_t size) {
		if (!connected_)
			throw connection_closed_error{};
		std::string read_data;
		while (read_data.size() < size) {
			char buffer[50];
			auto count = recv(socket_, buffer, std::min<int>(size - read_data.length(), 50), 0);
			if (count < 0) {
				switch (const int error_no = WSAGetLastError()) {
					case WSAECONNABORTED:
						connected_ = false;
						throw connection_closed_error{};
					default:
						throw_error("recv");
				}
			}
			if (count == 0) {
				connected_ = false;
				break;
			}
			read_data.append(buffer, count);
		}
		return read_data;
	}

	std::size_t client::write(std::string_view buffer) {
		if (!connected_)
			return 0;
		auto const result = send(socket_, buffer.data(), buffer.size(), 0);
		if (result < 0) {
			close();
			throw_error("send");
		}
		return result;
	}

	bool client::finish() {
		return connected_ && shutdown(socket_, SD_SEND) != SOCKET_ERROR;
	}

	void client::close() {
		::closesocket(socket_);
		socket_ = INVALID_SOCKET;
		connected_ = false;
	}

	std::size_t client::available() {
		unsigned long avail = 0;
		if (const auto result = ioctlsocket(socket_, FIONREAD, &avail); result)
			throw_error("ioctlsocket(., FIONREAD, .)");
		return avail;
	}

	client::~client() {
		WSACleanup();
	}


}
