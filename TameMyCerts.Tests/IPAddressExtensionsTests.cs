using System.Net;
using TameMyCerts.ClassExtensions;
using Xunit;

namespace TameMyCerts.Tests;

public class IPAddressExtensionsTests
{
    [Fact]
    public void Invalid_data_is_no_match()
    {
        Assert.False(IPAddress.Parse("10.0.0.1").IsInRange("10.0.0.0/test"));
        Assert.False(IPAddress.Parse("10.0.0.1").IsInRange("test"));
        Assert.False(IPAddress.Parse("10.0.0.1").IsInRange("test/0"));
        Assert.False(IPAddress.Parse("10.0.0.1").IsInRange("test/-1"));
        Assert.False(IPAddress.Parse("192.168.0.1").IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.False(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/33"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/-1"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/129"));
    }

    [Fact]
    public void IPv4_in_subnet_is_match()
    {
        Assert.True(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/0"));
        Assert.True(IPAddress.Parse("10.0.0.1").IsInRange("0.0.0.0/0"));
        Assert.True(IPAddress.Parse("172.16.0.1").IsInRange("0.0.0.0/0"));
        Assert.True(IPAddress.Parse("192.168.0.1").IsInRange("0.0.0.0/0"));
        Assert.True(IPAddress.Parse("255.255.255.255").IsInRange("0.0.0.0/0"));
        Assert.True(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/32"));
        Assert.True(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/24"));
        Assert.True(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/24"));
        Assert.True(IPAddress.Parse("192.168.0.255").IsInRange("192.168.0.0/24"));
        Assert.True(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/16"));
        Assert.True(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/16"));
        Assert.True(IPAddress.Parse("192.168.255.255").IsInRange("192.168.0.0/16"));
        Assert.True(IPAddress.Parse("172.16.0.0").IsInRange("172.16.0.0/12"));
        Assert.True(IPAddress.Parse("172.16.0.1").IsInRange("172.16.0.0/12"));
        Assert.True(IPAddress.Parse("172.31.255.255").IsInRange("172.16.0.0/12"));
        Assert.True(IPAddress.Parse("10.0.0.0").IsInRange("10.0.0.0/8"));
        Assert.True(IPAddress.Parse("10.0.0.1").IsInRange("10.0.0.0/8"));
        Assert.True(IPAddress.Parse("10.255.255.255").IsInRange("10.0.0.0/8"));
        Assert.True(IPAddress.Parse("192.168.5.1").IsInRange("192.168.5.85/24"));
        Assert.True(IPAddress.Parse("192.168.5.254").IsInRange("192.168.5.85/24"));
        Assert.True(IPAddress.Parse("10.128.240.48").IsInRange("10.128.240.50/30"));
        Assert.True(IPAddress.Parse("10.128.240.49").IsInRange("10.128.240.50/30"));
        Assert.True(IPAddress.Parse("10.128.240.50").IsInRange("10.128.240.50/30"));
        Assert.True(IPAddress.Parse("10.128.240.51").IsInRange("10.128.240.50/30"));
        Assert.True(IPAddress.Parse("0.0.0.0").IsInRange("192.168.5.85/0"));
        Assert.True(IPAddress.Parse("255.255.255.255").IsInRange("192.168.5.85/0"));
    }

    [Fact]
    public void IPv4_not_in_subnet_is_no_match()
    {
        Assert.False(IPAddress.Parse("0.0.0.1").IsInRange("0.0.0.0/32"));
        Assert.False(IPAddress.Parse("10.0.0.1").IsInRange("0.0.0.0/32"));
        Assert.False(IPAddress.Parse("172.16.0.1").IsInRange("0.0.0.0/32"));
        Assert.False(IPAddress.Parse("192.168.0.1").IsInRange("0.0.0.0/32"));
        Assert.False(IPAddress.Parse("255.255.255.255").IsInRange("0.0.0.0/32"));
        Assert.False(IPAddress.Parse("11.0.0.1").IsInRange("10.0.0.0/8"));
        Assert.False(IPAddress.Parse("172.32.0.1").IsInRange("172.16.0.0/16"));
        Assert.False(IPAddress.Parse("192.169.0.1").IsInRange("192.168.0.0/16"));
        Assert.False(IPAddress.Parse("192.168.1.1").IsInRange("192.168.0.0/24"));
        Assert.False(IPAddress.Parse("192.168.4.254").IsInRange("192.168.5.85/24"));
        Assert.False(IPAddress.Parse("191.168.5.254").IsInRange("192.168.5.85/24"));
        Assert.False(IPAddress.Parse("10.128.240.47").IsInRange("10.128.240.50/30"));
        Assert.False(IPAddress.Parse("10.128.240.52").IsInRange("10.128.240.50/30"));
        Assert.False(IPAddress.Parse("10.128.239.50").IsInRange("10.128.240.50/30"));
        Assert.False(IPAddress.Parse("10.127.240.51").IsInRange("10.128.240.50/30"));
    }

    [Fact]
    public void IPv6_in_subnet_is_match()
    {
        Assert.True(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.True(IPAddress.Parse("2001:0DB8:ABCD:0012:FFFF:FFFF:FFFF:FFFF")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.True(IPAddress.Parse("2001:0DB8:ABCD:0012:0001:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.True(IPAddress.Parse("2001:0DB8:ABCD:0012:FFFF:FFFF:FFFF:FFF0")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.True(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/128"));
        Assert.True(IPAddress.Parse("2001:0db8:abcd:5000:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:5678::0/53"));
        Assert.True(IPAddress.Parse("2001:0db8:abcd:57ff:ffff:ffff:ffff:ffff")
            .IsInRange("2001:db8:abcd:5678::0/53"));
        Assert.True(IPAddress.Parse("::")
            .IsInRange("2001:db8:abcd:0012::0/0"));
        Assert.True(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
            .IsInRange("2001:db8:abcd:0012::0/0"));
    }

    [Fact]
    public void IPv6_not_in_subnet_is_no_match()
    {
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0011:FFFF:FFFF:FFFF:FFFF")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0013:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0013:0001:0000:0000:0000")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0011:FFFF:FFFF:FFFF:FFF0")
            .IsInRange("2001:db8:abcd:0012::0/64"));
        Assert.False(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0001")
            .IsInRange("2001:db8:abcd:0012::0/128"));
        Assert.False(IPAddress.Parse("2001:0db8:abcd:4999:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:5678::0/53"));
        Assert.False(IPAddress.Parse("2001:0db8:abcd:5800:0000:0000:0000:0000")
            .IsInRange("2001:db8:abcd:5678::0/53"));
    }
}