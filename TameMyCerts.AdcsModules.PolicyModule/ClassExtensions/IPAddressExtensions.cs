// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace TameMyCerts.AdcsModules.PolicyModule.ClassExtensions;

internal static class IPAddressExtensions
{
    /// <summary>
    ///     Determines if the given IP address is within the specified subnet.
    /// </summary>
    /// <param name="address">The IP address to check.</param>
    /// <param name="subnetMask">The subnet in CIDR notation (e.g., "192.168.1.0/24").</param>
    /// <returns>True if the address is in the subnet; otherwise, false.</returns>
    public static bool IsInRange(this IPAddress address, string subnetMask)
    {
        if (string.IsNullOrWhiteSpace(subnetMask))
        {
            return false;
        }

        var parts = subnetMask.Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var maskAddress))
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var maskLength))
        {
            return false;
        }

        if (maskLength == 0)
        {
            return true;
        }

        if (maskLength < 0 || maskAddress.AddressFamily != address.AddressFamily)
        {
            return false;
        }

        switch (maskAddress.AddressFamily)
        {
            case AddressFamily.InterNetwork:
            {
                if (maskLength > 32)
                {
                    return false;
                }

                var maskBytes = maskAddress.GetAddressBytes();
                var addressBytes = address.GetAddressBytes();

                var mask = maskLength == 0 ? 0 : uint.MaxValue << (32 - maskLength);
                var maskAddr = BinaryPrimitives.ReadUInt32BigEndian(maskBytes);
                var ipAddr = BinaryPrimitives.ReadUInt32BigEndian(addressBytes);

                return (ipAddr & mask) == (maskAddr & mask);
            }
            case AddressFamily.InterNetworkV6:
            {
                if (maskLength > 128)
                {
                    return false;
                }

                var maskBytes = maskAddress.GetAddressBytes();
                var addressBytes = address.GetAddressBytes();

                if (maskBytes.Length != addressBytes.Length)
                {
                    return false;
                }

                var fullBytes = maskLength / 8;
                var remainingBits = maskLength % 8;

                for (var i = 0; i < fullBytes; i++)
                {
                    if (addressBytes[i] != maskBytes[i])
                    {
                        return false;
                    }
                }

                if (remainingBits > 0)
                {
                    int maskByte = (byte)(0xFF << (8 - remainingBits));
                    if ((addressBytes[fullBytes] & maskByte) != (maskBytes[fullBytes] & maskByte))
                    {
                        return false;
                    }
                }

                return true;
            }
            default:
                return false;
        }
    }
}