using System;
using System.Text;

namespace Zyborg.Lockbox
{
    public class Crypto : ICrypto
    {
        private static Crypto _instance;

        public static ICrypto Get() => _instance ?? (_instance = new Crypto());

        public byte[] DeriveKey(string password, out byte[] salt)
        {
            salt = Sodium.PasswordHash.ArgonGenerateSalt();
            return DeriveKey(password, salt, 32);
        }
        public byte[] DeriveKey(string password, byte[] salt)
        {
            return DeriveKey(password, salt, 32);
        }

        public byte[] DeriveKey(string password, byte[] salt, int length)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var passwordKey = Sodium.PasswordHash.ArgonHashBinary(passwordBytes, salt,
                limit: Sodium.PasswordHash.StrengthArgon.Sensitive,
                outputLength: length);
            
            return passwordKey;
        }

        public byte[] GenerateKey()
        {
            return Sodium.SecretBox.GenerateKey();
        }

        public byte[] GenerateNonce()
        {
            return Sodium.SecretBox.GenerateNonce();
        }

        public byte[] Encrypt(byte[] key, byte[] nonce, byte[] clear)
        {
            return Sodium.SecretBox.Create(clear, nonce, key);
        }

        public byte[] Decrypt(byte[] key, byte[] nonce, byte[] crypt)
        {
            return Sodium.SecretBox.Open(crypt, nonce, key);
        }

        public byte[] Encrypt(byte[] key, byte[] clear)
        {
            var nonce = Sodium.SecretBox.GenerateNonce();
            var crypt = Sodium.SecretBox.Create(clear, nonce, key);
            return SerUtil.PackBytes(nonce, crypt);
        }

        public byte[] Decrypt(byte[] key, byte[] cryptPack)
        {
            var bytes = SerUtil.UnpackBytes(cryptPack);
            if (bytes.Length != 2 || bytes[0].Length == 0 || bytes[1].Length == 0)
                throw new System.IO.InvalidDataException("malformed cryptPack payload");
                
            var nonce = bytes[0];
            var crypt = bytes[1];
            return Sodium.SecretBox.Open(crypt, nonce, key);
        }

        public void GenerateKeyPair(out byte[] pubKey, out byte[] prvKey)
        {
            var kp = Sodium.PublicKeyBox.GenerateKeyPair();
            pubKey = kp.PublicKey;
            prvKey = kp.PrivateKey;
        }

        public void GenerateKeyPair(byte[] key, out byte[] pubKey, out byte[] prvKeyCrypt)
        {
            var kp = Sodium.PublicKeyBox.GenerateKeyPair();
            pubKey = kp.PublicKey;
            prvKeyCrypt = Encrypt(key, kp.PrivateKey);
        }

        public byte[] EncryptAsym(byte[] pubKey, byte[] clear)
        {
            var crypt = Sodium.SealedPublicKeyBox.Create(clear, pubKey);
            return crypt;
        }

        public byte[] DecryptAsym(byte[] pubKey, byte[] prvKey, byte[] crypt)
        {
            var clear = Sodium.SealedPublicKeyBox.Open(crypt, prvKey, pubKey);
            return clear;
        }

        public void GenerateSigKeyPair(out byte[] pubKey, out byte[] prvKey)
        {
            var kp = Sodium.PublicKeyAuth.GenerateKeyPair();
            pubKey = kp.PublicKey;
            prvKey = kp.PrivateKey;
        }

        public void GenerateSigKeyPair(byte[] key, out byte[] pubKey, out byte[] prvKeyCrypt)
        {
            GenerateSigKeyPair(out pubKey, out var prvKey);
            prvKeyCrypt = Encrypt(key, prvKey);
        }

        public byte[] Sign(byte[] prvKey, byte[] data)
        {
            var signed = Sodium.PublicKeyAuth.Sign(data, prvKey);
            return signed;
        }

        public byte[] Verify(byte[] pubKey, byte[] signed)
        {
            var ver = Sodium.PublicKeyAuth.Verify(signed, pubKey);
            return ver;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~Crypto()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }

    public interface ICrypto : IDisposable
    {
        byte[] DeriveKey(string password, out byte[] salt);
        byte[] DeriveKey(string password, byte[] salt);
        byte[] GenerateKey();
        byte[] Encrypt(byte[] key, byte[] clear);
        byte[] Decrypt(byte[] key, byte[] cryptPack);

        void GenerateKeyPair(out byte[] pubKey, out byte[] prvKey);
        void GenerateKeyPair(byte[] key, out byte[] pubKey, out byte[] prvKeyCrypt);
        byte[] EncryptAsym(byte[] pubKey, byte[] clear);
        byte[] DecryptAsym(byte[] pubKey, byte[] prvKey, byte[] crypt);

        void GenerateSigKeyPair(out byte[] pubKey, out byte[] prvKey);
        void GenerateSigKeyPair(byte[] key, out byte[] pubKey, out byte[] prvKeyCrypt);
        byte[] Sign(byte[] prvKey, byte[] data);
        byte[] Verify(byte[] pubKey, byte[] signed);
    }
}
