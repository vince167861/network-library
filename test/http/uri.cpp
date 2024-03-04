#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "http/uri.h"

using namespace testing;
using namespace network;

TEST(uri, remove_dot_segments) {
	EXPECT_THAT(
		uri::from("/a/b/c/./../../g"),
		FieldsAre("", "", "", 0, "/a/g", "", ""));
}

TEST(uri, relative) {
	const auto base_uri = uri::from("http://a/b/c/d;p?q");
	const std::map<std::string_view, std::string_view> test_vector{
		{"g:h",			"g:h"},
		{"g",				"http://a/b/c/g"},
		{"./g",			"http://a/b/c/g"},
		{"g/",			"http://a/b/c/g/"},
		{"/g",			"http://a/g"},
		{"//g",			"http://g"},
		{"?y",			"http://a/b/c/d;p?y"},
		{"g?y",			"http://a/b/c/g?y"},
		{"#s",			"http://a/b/c/d;p?q#s"},
		{"g#s",			"http://a/b/c/g#s"},
		{"g?y#s",			"http://a/b/c/g?y#s"},
		{";x",			"http://a/b/c/;x"},
		{"",				"http://a/b/c/d;p?q"},
		{".",				"http://a/b/c/"},
		{"./",			"http://a/b/c/"},
		{"..",			"http://a/b/"},
		{"../",			"http://a/b/"},
		{"../g",			"http://a/b/g"},
		{"../..",			"http://a/"},
		{"../../",		"http://a/"},
		{"../../g",		"http://a/g"},
		{"../../../g",	"http://a/g"},
		{"../../../../g",	"http://a/g"},
		{"/./g",			"http://a/g"},
		{"/../g",			"http://a/g"},
		{"g.",			"http://a/b/c/g."},
		{".g",			"http://a/b/c/.g"},
		{"g..",			"http://a/b/c/g.."},
		{"..g",			"http://a/b/c/..g"}
	};
	for (auto& [from, target]: test_vector)
		EXPECT_EQ(base_uri.from_relative(from).to_absolute(), target) << "from: " << from;
}

TEST(uri, parse_valid) {
	EXPECT_THAT(
			uri::from("http://www.example.com"),
			FieldsAre("http", "", "www.example.com", 0, "", "", ""));
	EXPECT_THAT(
			uri::from("https://example.com:79?a20=b39"),
			FieldsAre("https", "", "example.com", 79, "", "a20=b39", ""));
	EXPECT_THAT(
			uri::from("happy+face://a%40b:c@www.gookle.com.lla:/ppa/aap?df=fd#ddddd"),
			FieldsAre("happy+face", "a@b:c", "www.gookle.com.lla", 0, "/ppa/aap", "df=fd", "ddddd"));
	EXPECT_THAT(
			uri::from("urn:example:ffghj:435"),
			FieldsAre("urn", "", "", 0, "example:ffghj:435", "", ""));
}

TEST(uri, parse_invalid) {
	EXPECT_THROW(uri::from("1hts:urk:aldjf?aa"), std::invalid_argument);
	EXPECT_THROW(uri::from("ht^s:urk:aldjf#45"), std::invalid_argument);
}
