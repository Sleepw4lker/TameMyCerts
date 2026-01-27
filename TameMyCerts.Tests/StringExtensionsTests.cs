using System;
using TameMyCerts.ClassExtensions;
using Xunit;

namespace TameMyCerts.Tests;

public class StringExtensionsTests
{
    [Fact]
    public void ReplaceCaseInsensitive_ReplacesSingleOccurrence()
    {
        var input = "Hello World";
        var result = input.ReplaceCaseInsensitive("world", "Universe");
        Assert.Equal("Hello Universe", result);
    }

    [Fact]
    public void ReplaceCaseInsensitive_ReplacesMultipleOccurrences()
    {
        var input = "Cat cat cAt caT";
        var result = input.ReplaceCaseInsensitive("cat", "dog");
        Assert.Equal("dog dog dog dog", result);
    }

    [Fact]
    public void ReplaceCaseInsensitive_NoMatch_ReturnsOriginal()
    {
        var input = "Hello World";
        var result = input.ReplaceCaseInsensitive("planet", "Universe");
        Assert.Equal("Hello World", result);
    }

    [Fact]
    public void ReplaceCaseInsensitive_EmptyInput_ReturnsEmpty()
    {
        var input = "";
        var result = input.ReplaceCaseInsensitive("anything", "something");
        Assert.Equal("", result);
    }

    [Fact]
    public void ReplaceCaseInsensitive_NullInput_ThrowsArgumentNullException()
    {
        string input = null!;
        Assert.Throws<ArgumentNullException>(() => input.ReplaceCaseInsensitive("a", "b"));
    }

    [Fact]
    public void ReplaceCaseInsensitive_NullFrom_ThrowsArgumentNullException()
    {
        var input = "Hello";
        Assert.Throws<ArgumentNullException>(() => input.ReplaceCaseInsensitive(null!, "b"));
    }

    [Fact]
    public void ReplaceCaseInsensitive_NullTo_ReplacesWithEmpty()
    {
        var input = "Hello World";
        var result = input.ReplaceCaseInsensitive("world", string.Empty);
        Assert.Equal("Hello ", result);
    }
}