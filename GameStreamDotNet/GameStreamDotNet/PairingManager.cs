namespace GameStreamDotNet
{
    using System;
    using System.Text;
    using System.Threading.Tasks;

    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Security;
    using Windows.UI.Xaml.Controls;

    public abstract class PairingManager
    {
        private const string HexAlphabet = "0123456789abcdef";

        private static readonly int[] HexValues =
            new int[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        public PairingManager()
        {
            this.SecureRandom = new SecureRandom(new CryptoApiRandomGenerator());
        }

        protected SecureRandom SecureRandom { get; private set; }

        public abstract Task PairAsync(string ipAddress, TextBox outputTextBox);

        protected static string GenerateRandomPin()
        {
            return new Random().Next(10000).ToString("D4");
        }

        protected static byte[] SaltPin(byte[] salt, string pin)
        {
            byte[] saltedPin = new byte[salt.Length + pin.Length];
            Array.Copy(salt, 0, saltedPin, 0, salt.Length);
            Encoding.UTF8.GetBytes(pin, 0, pin.Length, saltedPin, salt.Length);

            return saltedPin;
        }

        protected static string BytesToHex(byte[] value)
        {
            StringBuilder result = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                result.Append(HexAlphabet[b >> 4]);
                result.Append(HexAlphabet[b & 0x0F]);
            }

            return result.ToString();
        }

        protected static byte[] HexToBytes(string value)
        {
            value = value.ToUpperInvariant();
            int numChars = value.Length;
            byte[] byteValue = new byte[numChars / 2];
            for (int i = 0; i < numChars; i += 2)
            {
                byteValue[i / 2] = (byte)(HexValues[value[i] - '0'] << 4 | HexValues[value[i + 1] - '0']);
            }

            return byteValue;
        }

        protected static byte[] ConcatenateByteArrays(params byte[][] byteArrays)
        {
            if (byteArrays.Length < 2)
            {
                throw new ArgumentException("Cannot concatenate less than two arrays.", nameof(byteArrays));
            }

            int totalLength = 0;
            for (int i = 0; i < byteArrays.Length; i++)
            {
                totalLength += byteArrays[i].Length;
            }

            byte[] result = new byte[totalLength];
            int position = 0;
            for (int i = 0; i < byteArrays.Length; i++)
            {
                Array.Copy(byteArrays[i], 0, result, position, byteArrays[i].Length);
                position += byteArrays[i].Length;
            }

            return result;
        }

        protected static byte[] HashData(IDigest hashAlgorithm, byte[] data)
        {
            byte[] hashedData = new byte[hashAlgorithm.GetDigestSize()];
            hashAlgorithm.BlockUpdate(data, 0, data.Length);
            hashAlgorithm.DoFinal(hashedData, 0);

            return hashedData;
        }

        protected static ICipherParameters GenerateCipherKey(byte[] key)
        {
            return new KeyParameter(key, 0, 16);
        }

        protected static byte[] DoAesCipher(bool encrypt, ICipherParameters key, byte[] data)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");

            int blockRoundedSize = ((data.Length + 15) / 16) * 16;
            byte[] blockRoundedData = new byte[blockRoundedSize];
            Array.Copy(data, blockRoundedData, blockRoundedSize);

            cipher.Init(encrypt, key);
            return cipher.DoFinal(blockRoundedData);
        }

        protected static bool VerifySignature(byte[] data, byte[] signature, ICipherParameters key)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(false, key);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(signature);
        }


        protected static byte[] SignData(byte[] data, ICipherParameters key)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, key);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        protected byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.SecureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
