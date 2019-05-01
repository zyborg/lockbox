using System;
using System.Collections.Generic;

namespace Zyborg.Lockbox.Messages
{
    public class CreateUserStartRequest
    {
        public string Email { get; set; }
        public byte[] MasterSalt { get; set; }
        public byte[] AsymPublicKey { get; set; }
        /// <summary>
        /// User's asymmetric private key
        /// wrapped using user's master key
        /// </summary>
        /// <value></value>
        public byte[] AsymPrivateKeyWrapped { get; set; }
    }

    public class CreateUserStartResponse
    {
        public byte[] ChallengeToken { get; set; }
        public byte[] ChallengeQuestion { get; set; }
    }

    public class CreateUserFinalRequest
    {
        public byte[] ChallengeToken { get; set; }
        public byte[] ChallengeAnswer { get; set; }
    }


    public class AuthStartRequest
    {
        public string Email { get; set; }
    }

    public class AuthStartResponse
    {
        public byte[] MasterSalt { get; set; }
        public byte[] AsymPublicKey { get; set; }
        public byte[] AsymPrivateKeyWrapped { get; set; }

        public byte[] ChallengeToken { get; set; }
        public byte[] ChallengeQuestion { get; set; }
    }

    public class AuthFinalRequest
    {
        public byte[] ChallengeToken { get; set; }
        public byte[] ChallengeAnswer { get; set; }
    }

    public class AuthFinalResponse
    {
        public string AclToken { get; set; }
    }

    public class GetSelfRequest
    { }

    public class GetSelfResponse
    {
        public byte[] MasterSalt { get; set; }
        public byte[] AsymPublicKey { get; set; }
        public byte[] AsymPrivateKeyWrapped { get; set; }
    }

    public class CreateBoxRequest
    {
        public string Label { get; set; }
        /// <summary>
        /// Box-specific symmetric encryption key,
        /// wrapped using owner's AsymPublicKey.
        /// </summary>
        /// <value></value>
        public byte[] KeyWrapped { get; set; }
    }

    public class GetSelfBoxRequest
    {
        public string Box { get; set; }
    }

    public class GetSelfBoxResponse : GetSelfResponse
    {
        public byte[] BoxKeyWrapped { get; set; }
    }

    public class CreateEntryRequest
    {
        public string Label { get; set; }
        public Dictionary<string, string> Values { get; set; }
        public Dictionary<string, byte[]> Secrets { get; set; }
    }

    public class GetSelfBoxEntryRequest
    {
        public string Box { get; set; }
        public string Entry { get; set; }
    }

    public class GetSelfBoxEntryResponse : GetSelfBoxResponse
    {
        public Dictionary<string, string> Values { get; set; }
        public Dictionary<string, byte[]> Secrets { get; set; }
    }
}
