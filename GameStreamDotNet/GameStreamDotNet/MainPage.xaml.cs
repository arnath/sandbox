namespace GameStreamDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices.WindowsRuntime;
    using System.Text;
    using System.Xml.Serialization;

    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.OpenSsl;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Core;
    using Windows.Storage.Streams;
    using Windows.UI.Xaml;
    using Windows.UI.Xaml.Controls;
    using Windows.Web.Http;

    public sealed partial class MainPage : Page
    {
        private const string HexAlphabet = "0123456789ABCDEF";

        private static readonly int[] HexValues =
            new int[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        private readonly SecureRandom secureRandom;

        public MainPage()
        {
            this.InitializeComponent();
            this.secureRandom = new SecureRandom();
        }

        private async void PairButton_Click(object sender, RoutedEventArgs e)
        {
            // Create and salt pin
            byte[] salt = this.GenerateRandomBytes(16);
            string pin = GenerateRandomPin();
            byte[] saltAndPin = SaltPin(salt, pin);

            outputTextBox.Text = $"Enter pin: {pin}";

            // Certificate issuer and name
            X509Name name = new X509Name("CN=NVIDIA GameStream Client");

            // Certificate serial number
            byte[] serialBytes = this.GenerateRandomBytes(8);
            BigInteger serial = new BigInteger(serialBytes).Abs();

            // Expires in 20 years
            DateTime now = DateTime.UtcNow;
            DateTime expiration = now.AddYears(20);

            // Asymmetric key pair
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(this.secureRandom, 2048);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetIssuerDN(name);
            generator.SetSerialNumber(serial);
            generator.SetNotBefore(now);
            generator.SetNotAfter(expiration);
            generator.SetSubjectDN(name);
            generator.SetPublicKey(keyPair.Public);

            X509Certificate certificate =
                generator.Generate(
                    new Asn1SignatureFactory("SHA1WithRSA", keyPair.Private));

            string keyString;
            using (StringWriter keyWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(keyWriter);
                pemWriter.WriteObject(keyPair);
                keyString = keyWriter.ToString();

                // Line endings must be UNIX style for GFE to accept the certificate.
                keyString.Replace("\r\n", "\n");
            }

            string certString;
            using (StringWriter certWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(certWriter);
                pemWriter.WriteObject(certificate);
                certString = certWriter.ToString();

                // Line endings must be UNIX style for GFE to accept the certificate.
                certString.Replace("\r\n", "\n");
            }

            byte[] pemCertBytes = Encoding.UTF8.GetBytes(certString);
            byte[] uniqueId = GenerateRandomBytes(8);

            // Get server certificate
            PairResponse pairResponse = null;
            using (HttpClient httpClient = new HttpClient())
            {
                string uriString =
                    string.Format(
                        "http://{0}:47989/pair?uniqueid={1}&devicename=roth&updateState=1&phrase=getservercert&salt={2}&clientcert={3}",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        BytesToHex(salt),
                        BytesToHex(pemCertBytes));
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
                {
                    using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                    {
                        outputTextBox.Text = $"Get server cert status code: {response.StatusCode}\n";
                        string responseContent = await response.Content.ReadAsStringAsync();

                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize((await response.Content.ReadAsInputStreamAsync()).AsStreamForRead()) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || !pairResponse.Paired)
            {
                outputTextBox.Text += "Pairing failed.\n";
                return;
            }

            if (string.IsNullOrEmpty(pairResponse.PlainCert))
            {
                outputTextBox.Text += "Pairing already in progress.\n";
                return;
            }

            // Parse server certificate
            byte[] serverCertBytes = HexToBytes(pairResponse.PlainCert);
            X509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(serverCertBytes);

            // Generate a random challenge and encrypt it using AES
            byte[] challenge = GenerateRandomBytes(16);
        }

        private static string GenerateRandomPin()
        {
            return new Random().Next(10000).ToString("D4");
        }

        private static byte[] SaltPin(byte[] salt, string pin)
        {
            byte[] saltedPin = new byte[salt.Length + pin.Length];
            Array.Copy(salt, 0, saltedPin, 0, salt.Length);
            Encoding.UTF8.GetBytes(pin, 0, pin.Length, saltedPin, salt.Length);

            return saltedPin;
        }

        private static string BytesToHex(byte[] value)
        {
            StringBuilder result = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                result.Append(HexAlphabet[b >> 4]);
                result.Append(HexAlphabet[b & 0xf]);
            }

            return result.ToString();
        }

        private static byte[] HexToBytes(string value)
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

        private static byte[] HashData(string hashAlgorithmName, byte[] data)
        {
            HashAlgorithmProvider hashAlgorithm = HashAlgorithmProvider.OpenAlgorithm(hashAlgorithmName);

            return hashAlgorithm.HashData(data.AsBuffer()).ToArray();
        }

        private static CryptographicKey GenerateAesKey(string hashAlgorithmName, byte[] data)
        {
            SymmetricKeyAlgorithmProvider symmetricKeyAlgorithm =
                SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcb);
            IBuffer keyMaterial = HashData(hashAlgorithmName, data).AsBuffer(0, 16);

            return symmetricKeyAlgorithm.CreateSymmetricKey(keyMaterial);
        }

        private static ICipherParameters GenerateCipherKey(byte[] key)
        {
            return new KeyParameter(key, 0, 16);
        }

        private static byte[] DoAesCipher(bool encrypt, ICipherParameters key, byte[] data)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");

            int blockRoundedSize = ((data.Length + 15) / 16) * 16;
            byte[] blockRoundedData = new byte[blockRoundedSize];
            Array.Copy(data, blockRoundedData, blockRoundedSize);

            cipher.Init(encrypt, key);
            return cipher.DoFinal(blockRoundedData);
        }

        private byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.secureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
