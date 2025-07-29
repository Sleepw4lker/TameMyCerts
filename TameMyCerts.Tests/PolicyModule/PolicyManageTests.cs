using System;
using System.Reflection;
using TameMyCerts.AdcsModules.PolicyModule;
using Xunit;

namespace TameMyCerts.Tests.PolicyModule;

public class PolicyManageTests
{
    private readonly PolicyManage _policyManage = new();

    private static Assembly GetTameMyCertsAssembly()
    {
        // Get the assembly containing the PolicyManage class (i.e., the main TameMyCerts assembly)
        return typeof(PolicyManage).Assembly;
    }

    [Theory]
    [InlineData("Name", typeof(AssemblyTitleAttribute))]
    [InlineData("Description", typeof(AssemblyDescriptionAttribute))]
    [InlineData("Copyright", typeof(AssemblyCopyrightAttribute))]
    [InlineData("File Version", typeof(AssemblyFileVersionAttribute))]
    //[InlineData("Product Version", typeof(AssemblyVersionAttribute))]
    public void GetProperty_KnownProperties_ReturnsAssemblyAttributeValue(string propertyName, Type attributeType)
    {
        // Arrange
        var assembly = GetTameMyCertsAssembly();
        var expected = attributeType switch
        {
            Type t when t == typeof(AssemblyTitleAttribute) =>
                ((AssemblyTitleAttribute)assembly.GetCustomAttribute(t))?.Title,
            Type t when t == typeof(AssemblyDescriptionAttribute) =>
                ((AssemblyDescriptionAttribute)assembly.GetCustomAttribute(t))?.Description,
            Type t when t == typeof(AssemblyCopyrightAttribute) =>
                ((AssemblyCopyrightAttribute)assembly.GetCustomAttribute(t))?.Copyright,
            Type t when t == typeof(AssemblyFileVersionAttribute) =>
                ((AssemblyFileVersionAttribute)assembly.GetCustomAttribute(t))?.Version,
            Type t when t == typeof(AssemblyVersionAttribute) =>
                ((AssemblyVersionAttribute)assembly.GetCustomAttribute(t))?.Version,
            _ => null
        };

        // Act
        var result = _policyManage.GetProperty(null, null, propertyName, 0);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void GetProperty_UnknownProperty_ReturnsUnknownPropertyMessage()
    {
        // Arrange
        var unknownProperty = "NonExistentProperty";

        // Act
        var result = _policyManage.GetProperty(null, null, unknownProperty, 0);

        // Assert
        Assert.Equal($"Unknown Property: {unknownProperty}", result);
    }

    [Fact]
    public void Configure_DoesNotThrow()
    {
        // Act & Assert
        var exception = Record.Exception(() => _policyManage.Configure("config", "storage", 123));
        Assert.Null(exception);
    }

    [Fact]
    public void SetProperty_DoesNotThrow()
    {
        // Arrange
        object dummy = "value";

        // Act & Assert
        var exception = Record.Exception(() => _policyManage.SetProperty("config", "storage", "Name", 0, ref dummy));
        Assert.Null(exception);
    }
}