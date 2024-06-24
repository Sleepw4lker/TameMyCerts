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

using System.Text.RegularExpressions;

namespace TameMyCerts.ClassExtensions
{
    public static class StringExtensions
    {
        public static string ReplaceCaseInsensitive(this string input, string from, string to)
        {
            return Regex.Replace(input, from, to, RegexOptions.IgnoreCase);
        }

        public static string Capitalize(this string s)
        {
            if (string.IsNullOrEmpty(s))
                return s;

            char[] a = s.ToCharArray();
            a[0] = char.ToUpper(a[0]);
            return new string(a);
        }
    }
}