using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Models;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class PatternTests
    {
        [TestMethod]
        public void Does_match_exactly_valid_term_case_sensitive()
        {
            var pattern = new Pattern
            {
                Expression = "ThisIsATest",
                TreatAs = "ExactMatch"
            };

            Assert.IsTrue(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_not_match_exactly_invalid_term_case_sensitive()
        {
            var pattern = new Pattern
            {
                Expression = "ThisIsATest",
                TreatAs = "ExactMatch"
            };

            Assert.IsFalse(pattern.IsMatch("thisisatest"));
        }

        [TestMethod]
        public void Does_match_exactly_valid_term_case_insensitive()
        {
            var pattern = new Pattern
            {
                Expression = "ThisIsATest",
                TreatAs = "ExactMatchIgnoreCase"
            };

            Assert.IsTrue(pattern.IsMatch("thisisatest"));
        }

        [TestMethod]
        public void Does_match_valid_RegEx_valid_term_case_sensitive()
        {
            var pattern = new Pattern
            {
                Expression = "^[a-zA-Z0-9]*$"
            };

            Assert.IsTrue(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_match_valid_RegEx_valid_term_case_insensitive()
        {
            var pattern = new Pattern
            {
                Expression = "^[a-z0-9]*$",
                TreatAs = "RegExIgnoreCase"
            };

            Assert.IsTrue(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_not_match_valid_RegEx_invalid_term()
        {
            var pattern = new Pattern
            {
                Expression = "^[a-z0-9]*$"
            };

            Assert.IsFalse(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_not_match_invalid_RegEx()
        {
            var pattern = new Pattern
            {
                Expression = "thisisnotvalid"
            };

            Assert.IsFalse(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_not_match_invalid_TreatAs()
        {
            var pattern = new Pattern
            {
                Expression = "^[a-z0-9]*$",
                TreatAs = "thisisnotvalid"
            };

            Assert.IsFalse(pattern.IsMatch("ThisIsATest"));
        }

        [TestMethod]
        public void Does_match_invalid_TreatAs_MatchOnError()
        {
            var pattern = new Pattern
            {
                Expression = "^[a-z0-9]*$",
                TreatAs = "thisisnotvalid"
            };

            Assert.IsTrue(pattern.IsMatch("ThisIsATest", true));
        }

        [TestMethod]
        public void Does_match_valid_Cidr_valid_term()
        {
            var pattern = new Pattern
            {
                Expression = "192.168.0.0/24",
                TreatAs = "Cidr"
            };

            Assert.IsTrue(pattern.IsMatch("192.168.0.1"));
        }

        [TestMethod]
        public void Does_not_match_invalid_Cidr_valid_term()
        {
            var pattern = new Pattern
            {
                Expression = "thisisnotvalid",
                TreatAs = "Cidr"
            };

            Assert.IsFalse(pattern.IsMatch("192.168.0.1"));
        }
    }
}