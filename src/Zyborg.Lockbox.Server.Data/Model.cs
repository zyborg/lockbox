using System;

namespace Zyborg.Lockbox.Server.Data
{
    public class UserEntity
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
        public byte[] MasterSalt { get; set; }

        public byte[] AsymPublicKey { get; set; }
        public byte[] AsymPrivateKeyWrapped { get; set; }

        public byte[] SigPublicKey { get; set; }
        public byte[] SigPrivateKeyWrapped { get; set; }
    }

    public class BoxEntity
    {
        public Guid Id { get; set; }
        public UserEntity Owner { get; set; }
        public string Label { get; set; }
    }
    
    public class UserBoxEntity
    {
        public Guid Id { get; set; }
        public UserEntity User { get; set; }
        public BoxEntity Box { get; set; }
        public byte[] KeyWrapped { get; set; }
    }

    public class EntryEntity
    {
        public Guid Id { get; set; }
        public BoxEntity Box { get; set; }
        public int Ver { get; set; }
        public string Label { get; set; }
    }

    public class FieldEntity
    {
        public Guid Id { get; set; }
        public EntryEntity Entry { get; set; }
        public int Ver { get; set; }
        public string Name { get; set; }
        public string ClearValue { get; set; }
        public byte[] CryptValue { get; set; }
    }

    public class SessionEntity
    {
        public Guid Id { get; set; }
        public Guid AccessId { get; set; }

        public UserEntity User { get; set; }
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
    }
}