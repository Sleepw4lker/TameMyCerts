// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace TameMyCerts.ClassExtensions
{
    internal static class IPAddressExtensions
    {
        /// <summary>
        ///     This code was adopted from a sample provided by Christoph Sonntag thus all credits go to the original author
        /// </summary>
        /// <param name="address"></param>
        /// <param name="subnetMask"></param>
        /// <see cref="https://stackoverflow.com/questions/1499269" />
        /// <returns></returns>
        public static bool IsInRange(this IPAddress address, string subnetMask)
        {
            IPAddress maskAddress;
            int maskLength;

            try
            {
                var parts = subnetMask.Split('/');

                maskAddress = IPAddress.Parse(parts[0]);
                maskLength = int.Parse(parts[1]);
            }
            catch
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

                    var maskAddressBits = BitConverter.ToInt32(maskAddress.GetAddressBytes(), 0);
                    var ipAddressBits = BitConverter.ToInt32(address.GetAddressBytes(), 0);
                    var maskBits = IPAddress.HostToNetworkOrder(-1 << (32 - maskLength));

                    return (ipAddressBits & maskBits) == (maskAddressBits & maskBits);
                }
                case AddressFamily.InterNetworkV6:
                {
                    if (maskLength > 128)
                    {
                        return false;
                    }

                    var maskAddressBits = new BitArray(maskAddress.GetAddressBytes().Reverse().ToArray());
                    var ipAddressBits = new BitArray(address.GetAddressBytes().Reverse().ToArray());

                    if (maskAddressBits.Length != ipAddressBits.Length)
                    {
                        return false;
                    }

                    for (var i = ipAddressBits.Length - 1; i >= ipAddressBits.Length - maskLength; i--)
                    {
                        if (ipAddressBits[i] != maskAddressBits[i])
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
}