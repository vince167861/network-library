#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "http/url.h"

using namespace testing;
using namespace leaf::network;

TEST(url, parse_valid) {
	EXPECT_THAT(
			url{"http://www.example.com"},
			FieldsAre("http", "", "", "www.example.com", 0, "", IsEmpty(), ""));
	EXPECT_THAT(
			url{"https://example.com:79?a20=b39"},
			FieldsAre("https", "", "", "example.com", 79, "", UnorderedElementsAre(Pair("a20", "b39")), ""));
	EXPECT_THAT(
			url{"ftp://a@b@www.gookle.com.lla:/ppa/aap?df=fd#ddddd"},
			FieldsAre("ftp", "a@b", "", "www.gookle.com.lla", 0, "/ppa/aap", UnorderedElementsAre(Pair("df", "fd")), "ddddd")
			);
	EXPECT_THAT(
			url{"happy+face://a@b:c@w.lla/ppa/aap/#ddddd"},
			FieldsAre("happy+face", "a@b", "c", "w.lla", 0, "/ppa/aap/", IsEmpty(), "ddddd"));
	EXPECT_THAT(
			url{"urn:example:ffghj:435"},
			FieldsAre("urn", "", "", "", 0, "example:ffghj:435", IsEmpty(), ""));
}

TEST(url, parse_invalid) {
	EXPECT_THROW(url{"1hts:urk:aldjf?aa"}, std::runtime_error);
	EXPECT_THROW(url{"ht^s:urk:aldjf#45"}, std::runtime_error);
}
