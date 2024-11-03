using TameMyCerts.Models;
using Xunit;

namespace TameMyCerts.Tests;

public class PatternTests
{
    [Fact]
    public void Does_match_exactly_valid_term_case_sensitive()
    {
        var pattern = new Pattern
        {
            Expression = "ThisIsATest",
            TreatAs = "ExactMatch"
        };

        Assert.True(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_not_match_exactly_invalid_term_case_sensitive()
    {
        var pattern = new Pattern
        {
            Expression = "ThisIsATest",
            TreatAs = "ExactMatch"
        };

        Assert.False(pattern.IsMatch("thisisatest"));
    }

    [Fact]
    public void Does_match_exactly_valid_term_case_insensitive()
    {
        var pattern = new Pattern
        {
            Expression = "ThisIsATest",
            TreatAs = "ExactMatchIgnoreCase"
        };

        Assert.True(pattern.IsMatch("thisisatest"));
    }

    [Fact]
    public void Does_match_valid_RegEx_valid_term_case_sensitive()
    {
        var pattern = new Pattern
        {
            Expression = "^[a-zA-Z0-9]*$"
        };

        Assert.True(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_match_valid_RegEx_valid_term_case_insensitive()
    {
        var pattern = new Pattern
        {
            Expression = "^[a-z0-9]*$",
            TreatAs = "RegExIgnoreCase"
        };

        Assert.True(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_not_match_valid_RegEx_invalid_term()
    {
        var pattern = new Pattern
        {
            Expression = "^[a-z0-9]*$"
        };

        Assert.False(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_not_match_invalid_RegEx()
    {
        var pattern = new Pattern
        {
            Expression = "thisisnotvalid"
        };

        Assert.False(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_not_match_invalid_TreatAs()
    {
        var pattern = new Pattern
        {
            Expression = "^[a-z0-9]*$",
            TreatAs = "thisisnotvalid"
        };

        Assert.False(pattern.IsMatch("ThisIsATest"));
    }

    [Fact]
    public void Does_match_invalid_TreatAs_MatchOnError()
    {
        var pattern = new Pattern
        {
            Expression = "^[a-z0-9]*$",
            TreatAs = "thisisnotvalid"
        };

        Assert.True(pattern.IsMatch("ThisIsATest", true));
    }

    [Fact]
    public void Does_match_valid_Cidr_valid_term()
    {
        var pattern = new Pattern
        {
            Expression = "192.168.0.0/24",
            TreatAs = "Cidr"
        };

        Assert.True(pattern.IsMatch("192.168.0.1"));
    }

    [Fact]
    public void Does_not_match_invalid_Cidr_valid_term()
    {
        var pattern = new Pattern
        {
            Expression = "thisisnotvalid",
            TreatAs = "Cidr"
        };

        Assert.False(pattern.IsMatch("192.168.0.1"));
    }
}