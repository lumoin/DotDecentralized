﻿using System;

namespace Verifiable.Core.Did.Methods
{
    public static class WellKnownDidMethodPrefixes
    {
        /// <summary>
        /// 
        /// </summary>
        public static string KeyDidPrefix { get; } = "did:key:";

        /// <summary>
        /// If <paramref name="didPrefix"/> is <see cref="KeyDidPrefix"/> or not.
        /// </summary>
        /// <param name="didPrefix">The did method prefix.</param>.
        /// <returns><see langword="true" /> if  <paramref name="didPrefix"/> is <see cref="KeyDidPrefix"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKeyDidPrefix(string didPrefix) => Equals(KeyDidPrefix, didPrefix);

        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="didPrefix">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="didPrefix"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string didPrefix) => didPrefix switch
        {
            string _ when IsKeyDidPrefix(didPrefix) => KeyDidPrefix,
            string _ => didPrefix
        };


        /// <summary>
        /// Returns a value that indicates if the DID method prefixes are the same.
        /// </summary>
        /// <param name="didPrefixA">The first DID method prefix to compare.</param>
        /// <param name="didPrefixB">The second DID method prefix to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="didPrefixA"/> and <paramref name="didPrefixB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string didPrefixA, string didPrefixB)
        {
            return ReferenceEquals(didPrefixA, didPrefixB) || StringComparer.InvariantCulture.Equals(didPrefixA, didPrefixB);
        }
    }
}
