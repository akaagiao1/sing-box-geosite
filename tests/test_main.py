import unittest

from main import convert_text, output_name, parse_rule, split_rule_set


class ParseRuleTests(unittest.TestCase):
    def test_supported_formats(self):
        cases = {
            "DOMAIN-SUFFIX,example.com": ("domain_suffix", "example.com"),
            "host-keyword,google": ("domain_keyword", "google"),
            "IP-CIDR,10.0.0.1/8,no-resolve": ("ip_cidr", "10.0.0.1/8"),
            "+.example.org": ("domain_suffix", "example.org"),
            "plain.example": ("domain", "plain.example"),
            "2001:db8::/32": ("ip_cidr", "2001:db8::/32"),
            "PROCESS-NAME,Telegram.exe": ("process_name", "Telegram.exe"),
            "HOST-WILDCARD,*.google.*": ("domain_regex", r"^.*\.google\..*$"),
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(parse_rule(source), expected)

    def test_comments_and_unsupported_rules_are_ignored(self):
        self.assertIsNone(parse_rule("# comment"))
        self.assertIsNone(parse_rule("USER-AGENT,Example*"))
        self.assertIsNone(parse_rule("AND,((DOMAIN,a.example),(DOMAIN,b.example))"))


class ConversionTests(unittest.TestCase):
    def test_clash_yaml_is_deduplicated_and_sorted(self):
        result = convert_text(
            """payload:
  - DOMAIN,b.example
  - DOMAIN,a.example
  - DOMAIN,b.example
  - DOMAIN-SUFFIX,example.org
"""
        )
        self.assertEqual(
            result,
            {
                "version": 2,
                "rules": [
                    {"domain": ["a.example", "b.example"]},
                    {"domain_suffix": ["example.org"]},
                ],
            },
        )

    def test_plain_multiline_list_reads_every_line(self):
        result = convert_text("one.example\ntwo.example\n")
        self.assertEqual(
            result["rules"], [{"domain": ["one.example", "two.example"]}]
        )

    def test_clash_yaml_with_leading_comment(self):
        result = convert_text("# source metadata\npayload:\n  - DOMAIN,example.com\n")
        self.assertEqual(result["rules"], [{"domain": ["example.com"]}])

    def test_url_output_name(self):
        self.assertEqual(output_name("https://example.test/path/rules.list"), "rules")

    def test_mixed_rule_set_is_split_by_match_target(self):
        data = {
            "version": 2,
            "rules": [
                {"domain_suffix": ["example.cn"]},
                {"ip_cidr": ["1.0.1.0/24"]},
                {"process_name": ["example"]},
            ],
        }
        self.assertEqual(
            split_rule_set(data),
            {
                "domain": {"version": 2, "rules": [{"domain_suffix": ["example.cn"]}]},
                "ip": {"version": 2, "rules": [{"ip_cidr": ["1.0.1.0/24"]}]},
            },
        )

    def test_single_category_rule_set_is_not_split(self):
        data = {"version": 2, "rules": [{"domain": ["example.cn"]}]}
        self.assertEqual(split_rule_set(data), {})


if __name__ == "__main__":
    unittest.main()
