#pragma once

#include <list>
#include <map>
#include <memory>

namespace leaf::json {

	class element {
	public:
		static std::shared_ptr<element> parse(std::string_view);
	};


	class object: public element {
	public:
		using members_t = std::map<std::string, std::shared_ptr<element>>;

		members_t members;

		explicit object(std::string_view);

		explicit object(members_t);
	};


	class array: public element {
	public:
		using items_t = std::list<std::shared_ptr<element>>;

		items_t items;

		explicit array(items_t values);
	};


	class string: public element {
	public:
		std::string value;

		explicit string(std::string_view);

		explicit string(std::string);
	};


	class number: public element {
	public:
		double value;

		explicit number(std::string_view);

		explicit number(double value);
	};


	class null: public element {
	};


	class boolean: public element {
	public:
		bool value;

		explicit boolean(bool value);
	};


	class malformed_json final: public std::exception {
	};
}
