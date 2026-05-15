using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using TameMyCerts.Enums;

namespace TameMyCerts.ClassExtensions;

internal static class KeyAlgorithmTypeExtensions
{
    public static string GetAlgorithmName(this KeyAlgorithmType value)
    {
        var field = typeof(KeyAlgorithmType).GetField(value.ToString());
        return field?.GetCustomAttribute<AlgorithmNameAttribute>()?.Name
               ?? value.ToString();
    }

    public static IEnumerable<string> GetAllAlgorithmNames()
    {
        return Enum.GetValues<KeyAlgorithmType>()
            .Select(v => v.GetAlgorithmName());
    }

    public static IEnumerable<(KeyAlgorithmType Value, string Name)> GetAllAlgorithmsWithNames()
        => Enum.GetValues<KeyAlgorithmType>()
            .Select(v => (v, v.GetAlgorithmName()));

    public static bool TryParseAlgorithmName(string name, out KeyAlgorithmType result)
    {
        foreach (var value in Enum.GetValues<KeyAlgorithmType>())
        {
            if (value.GetAlgorithmName() != name)
            {
                continue;
            }

            result = value;
            return true;
        }

        result = default;
        return false;
    }
}