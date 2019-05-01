using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Zyborg.Lockbox.Tests
{
    public class CryptoTests
    {
        static readonly string TestPassword = "F00B@r2019!";

        static readonly byte[] TestSalt = new byte[] {
            0x4C, 0x46, 0xF3, 0xB7, 0x49, 0x94, 0x5F, 0x4C,
            0xE3, 0x46, 0x4F, 0x64, 0x6A, 0x78, 0x19, 0xCF, };
        static readonly byte[] TestKey = new byte[] {
            0x84, 0xC2, 0xB4, 0x7C, 0xEF, 0x8C, 0x4D, 0xDD,
            0xC9, 0x88, 0xEE, 0x2F, 0xBE, 0x97, 0x1B, 0x52,
            0xFD, 0x1D, 0x5A, 0x9C, 0xA5, 0x11, 0xF5, 0xAC,
            0x77, 0xE1, 0xCE, 0x13, 0x91, 0x56, 0x26, 0x84, };

        [Fact]
        public void TestDeriveAndRecoverKey()
        {
            var password = "F00B@r2019!";
            var crypto = Crypto.Get();
            var derived1 = crypto.DeriveKey(password, out var derivedSalt);
            var derived2 = crypto.DeriveKey(password, derivedSalt);

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            Assert.NotEqual(passwordBytes, derived1);
            Assert.NotEqual(passwordBytes, derived2);

            Assert.Equal(derived1, derived2);
        }

        [Fact]
        public void TestRecoverDerivedKey()
        {
            var crypto = Crypto.Get();

            // Uncomment to generate the test seed
            // var generated = crypto.DeriveKey(TestPassword);
            // throw new Exception($@"
            //     TestSalt = new byte[] {{ 0x{BitConverter.ToString(generated.salt).Replace("-", ", 0x")}, }};
            //     TestKey = new byte[] {{ 0x{BitConverter.ToString(generated.key).Replace("-", ", 0x")}, }};
            // ");

            var derived = crypto.DeriveKey(TestPassword, TestSalt);

            Assert.Equal(TestKey, derived);
        }

        [Fact]
        public void TestEncryptDecrypt()
        {
            var crypto = Crypto.Get();
            var text = "THIS IS GOING TO BE A TEST";
            var clear = Encoding.UTF8.GetBytes(text);
            var encrypted = crypto.Encrypt(TestKey, clear);
            var decrypted = crypto.Decrypt(TestKey, encrypted);
            var decryptedText = Encoding.UTF8.GetString(decrypted);

            Assert.Equal(clear, decrypted);
            Assert.Equal(text, decryptedText);
        }

        [Fact]
        public void TestAsymEncryptDecrypt()
        {
            var crypto = Crypto.Get();

            crypto.GenerateKeyPair(out var pubKey, out var prvKey);

            var text = "THIS IS GOING TO BE A TEST";
            var clear = Encoding.UTF8.GetBytes(text);
            var crypt = crypto.EncryptAsym(pubKey, clear);
            var reclear = crypto.DecryptAsym(pubKey, prvKey, crypt);
            var retext = Encoding.UTF8.GetString(reclear);
            Assert.Equal(text, retext);
        }

        [Fact]
        public void TestIdenticalSymEncrypt()
        {
            var crypto = (Crypto)Crypto.Get();

            var text = "THIS IS GOING TO BE A TEST";
            var clear = Encoding.UTF8.GetBytes(text);

            var key = crypto.GenerateKey();
            var nonce = crypto.GenerateNonce();
            var crypt1 = crypto.Encrypt(key, nonce, clear);
            var crypt2 = crypto.Encrypt(key, nonce, clear);
            Assert.Equal(crypt1, crypt2);
        }

        [Fact]
        public void TestUniqueAsymEncrypt()
        {
            var crypto = Crypto.Get();

            crypto.GenerateKeyPair(out var pubKey, out var prvKey);

            var text = "THIS IS GOING TO BE A TEST";
            var clear = Encoding.UTF8.GetBytes(text);
            var crypt1 = crypto.EncryptAsym(pubKey, clear);
            var crypt2 = crypto.EncryptAsym(pubKey, clear);

            Assert.NotEqual(crypt1, crypt2);
        }

        [Fact]
        public void TestVerify()
        {
            var crypto = Crypto.Get();

            crypto.GenerateSigKeyPair(out var pubKey, out var prvKey);

            var text = "THIS IS GOING TO BE A TEST";
            var data = Encoding.UTF8.GetBytes(text);
            var signed = crypto.Sign(prvKey, data);
            var verifiedData = crypto.Verify(pubKey, signed);
            var verifiedText = Encoding.UTF8.GetString(verifiedData);
            Assert.Equal(text, verifiedText);
            Assert.Equal(data, verifiedData);
        }

        [Fact]
        public void TestFailVerify()
        {
            var crypto = Crypto.Get();

            crypto.GenerateSigKeyPair(out var kp1Pub, out var kp1Prv);
            crypto.GenerateSigKeyPair(out var kp2Pub, out var kp2Prv);

            var text = "THIS IS GOING TO BE A TEST";
            var data = Encoding.UTF8.GetBytes(text);
            var signed = crypto.Sign(kp1Prv, data);

            Assert.Throws<CryptographicException>(() =>
                crypto.Verify(kp2Pub, signed));
        }
    }
}
