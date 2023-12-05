#include <gtest/gtest.h>

#include "json/json.h"

using namespace leaf::json;

TEST(json, boolean) {
	auto element_1 = element::parse("true");
	ASSERT_TRUE(element_1);
	ASSERT_TRUE(reinterpret_cast<boolean&>(*element_1).value);

	auto element_2 = element::parse("false");
	ASSERT_TRUE(element_2);
	ASSERT_FALSE(reinterpret_cast<boolean&>(*element_2).value);

	ASSERT_THROW(element::parse("t rue"), malformed_json);
}

TEST(json, string) {
	auto s1 = element::parse(R"a("true")a");
	ASSERT_TRUE(s1);
	ASSERT_EQ(reinterpret_cast<string&>(*s1).value, "true");

	auto s2 = element::parse(R"("\u1234\u5678")");
	ASSERT_TRUE(s2);
	ASSERT_EQ(reinterpret_cast<string&>(*s2).value, "\u1234\u5678");

	EXPECT_THROW(element::parse(R"a("true)a"), malformed_json);
	EXPECT_THROW(element::parse(R"a(tr""ue)a"), malformed_json);
}

TEST(json, number) {
	auto element_1 = element::parse("123");
	ASSERT_TRUE(element_1);
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*element_1).value, 123);
	auto element_2 = element::parse("123e2");
	ASSERT_TRUE(element_2);
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*element_2).value, 123e2);
	auto element_3 = element::parse("-123.0e2");
	ASSERT_TRUE(element_3);
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*element_3).value, -123.0e2);
	auto element_4 = element::parse("-1.32e-2");
	ASSERT_TRUE(element_4);
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*element_4).value, -1.32e-2);
	auto element_5 = element::parse("-1.32");
	ASSERT_TRUE(element_5);
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*element_5).value, -1.32);

	EXPECT_THROW(element::parse("123.e2"), malformed_json);
	EXPECT_THROW(element::parse("-01.32"), malformed_json);
}

TEST(json, null) {
	EXPECT_NO_THROW(element::parse("null"));

	EXPECT_THROW(element::parse("nul"), malformed_json);
}

TEST(json, object) {
	auto element_1 = element::parse(R"({"name1": "value1"})");
	ASSERT_TRUE(element_1);
	auto& members_1 = reinterpret_cast<object&>(*element_1).members;
	EXPECT_EQ(reinterpret_cast<string&>(*members_1.at("name1")).value, "value1");

	auto element_2 = element::parse(R"({"name1": "value1", " name2": 123})");
	ASSERT_TRUE(element_2);
	auto& members_2 = reinterpret_cast<object&>(*element_2).members;
	EXPECT_EQ(reinterpret_cast<string&>(*members_2.at("name1")).value, "value1");
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*members_2.at(" name2")).value, 123);

	auto element_3
			= element::parse(R"({"name1": "value1", )" "\t" R"(" name2": 123,  "n ame3"  :null  })");
	ASSERT_TRUE(element_3);
	auto& members_3 = reinterpret_cast<object&>(*element_3).members;
	EXPECT_EQ(reinterpret_cast<string&>(*members_3.at("name1")).value, "value1");
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*members_3.at(" name2")).value, 123);
	EXPECT_TRUE(members_3.at("n ame3"));

	auto element_4
			= element::parse(R"({"name1": "value1", " name2": 123,  "n ame3"  :null  , "": "i am nu\tll"})");
	ASSERT_TRUE(element_4);
	auto& members_4 = reinterpret_cast<object&>(*element_4).members;
	EXPECT_EQ(reinterpret_cast<string&>(*members_4.at("name1")).value, "value1");
	EXPECT_DOUBLE_EQ(reinterpret_cast<number&>(*members_4.at(" name2")).value, 123);
	EXPECT_TRUE(members_4.at("n ame3"));
	EXPECT_EQ(reinterpret_cast<string&>(*members_4.at("")).value, "i am nu\tll");
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}
