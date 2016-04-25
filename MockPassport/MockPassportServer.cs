using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace MockPassport
{
    public static class MockPassportServer
    {
        public static void SavePublicKeyForUser(string user, string publickey)
        {
            //save the public key for this user
            var container = Windows.Storage.ApplicationData.Current.LocalSettings.CreateContainer("hello_data", Windows.Storage.ApplicationDataCreateDisposition.Always);
            container.Values[user] = publickey;
        }

        public static string CreateChallenge()
        {
            const int PASSWORD_SALT_LENGTH = 32;
            IBuffer randomBuffer = CryptographicBuffer.GenerateRandom(PASSWORD_SALT_LENGTH);
            string randomString = CryptographicBuffer.EncodeToBase64String(randomBuffer);

            return randomString;
        }

        public static bool VerifySignature(string user, string challenge, string signature)
        {
            var publicKey = GetPublicKeyForUser(user);
            if (null == publicKey)
            {
                return false;
            }

            IBuffer challengeBuffer = CryptographicBuffer.DecodeFromBase64String(challenge);
            IBuffer signatureBuffer = CryptographicBuffer.DecodeFromBase64String(signature);
            IBuffer publicKeyBuffer = CryptographicBuffer.DecodeFromBase64String(publicKey);

            var rsa = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPkcs1Sha256);
            var rsakey = rsa.ImportPublicKey(publicKeyBuffer, CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey);
            return CryptographicEngine.VerifySignature(rsakey, challengeBuffer, signatureBuffer);
        }

        private static string GetPublicKeyForUser(string user)
        {
            var container = Windows.Storage.ApplicationData.Current.LocalSettings.CreateContainer("hello_data", Windows.Storage.ApplicationDataCreateDisposition.Always);
            object pk;
            if (!container.Values.TryGetValue(user, out pk))
            {
                pk = null;
            }

            return pk as string;
        }
    }
}