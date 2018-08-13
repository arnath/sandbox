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
    using Org.BouncyCastle.Crypto.Digests;
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
            // Create SHA256 hash digest. This is not supported by server version < 7
            // (need to use SHA1 for those cases) but that doesn't really matter right now.
            IDigest hashAlgorithm = new Sha256Digest();
            int hashDigestSize = hashAlgorithm.GetDigestSize();

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

            // Get server certificate.
            // TODO: Call should have no timeout because it requires the user to enter a pin.
            PairResponse pairResponse = null;
            using (HttpClient httpClient = new HttpClient())
            {
                string uriString =
                    string.Format(
                        "http://{0}:47989/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&phrase=getservercert&salt={3}&clientcert={4}",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        Guid.NewGuid(),
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

            // Hash the salt and pin and use it to generate an AES key. 
            byte[] hashedSaltAndPin = HashData(hashAlgorithm, saltAndPin);
            ICipherParameters aesKey = GenerateCipherKey(hashedSaltAndPin);

            // Generate a random challenge and encrypt it using AES.
            byte[] challenge = GenerateRandomBytes(16);
            byte[] encryptedChallenge = DoAesCipher(true, aesKey, challenge);

            // Send the encrypted challenge to the server.
            // TODO: Call should have a timeout.
            using (HttpClient httpClient = new HttpClient())
            {
                string uriString =
                    string.Format(
                        "http://{0}:47989/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&clientchallenge={3}",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        Guid.NewGuid(),
                        BytesToHex(encryptedChallenge));
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
                {
                    using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                    {
                        outputTextBox.Text = $"Send challenge status code: {response.StatusCode}\n";
                        string responseContent = await response.Content.ReadAsStringAsync();

                        outputTextBox.Text += responseContent + "\n";
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

            // Decode the server's response and subsequent challenge.
            byte[] encryptedServerChallengeResponse = HexToBytes(pairResponse.ChallengeResponse);
            byte[] decryptedServerChallengeResponse = DoAesCipher(false, aesKey, encryptedServerChallengeResponse);

            byte[] serverResponse = new byte[hashDigestSize];
            byte[] serverChallenge = new byte[hashDigestSize];
            Array.Copy(decryptedServerChallengeResponse, serverResponse, hashDigestSize);
            Array.Copy(decryptedServerChallengeResponse, hashDigestSize, serverChallenge, 0, hashDigestSize);

            // Using another 16 byte secret, compute a challenge response hash using the secret, 
            // our certificate signature, and the challenge.
            byte[] clientSecret = GenerateRandomBytes(16);
            byte[] challengeResponseHash = 
                HashData(
                    hashAlgorithm, 
                    ConcatenateByteArrays(serverChallenge, certificate.GetSignature(), clientSecret));
            byte[] encryptedChallengeResponse = DoAesCipher(true, aesKey, challengeResponseHash);

            // Send the challenge response to the server.
            // TODO: Call should have a timeout.
            using (HttpClient httpClient = new HttpClient())
            {
                string uriString =
                    string.Format(
                        "http://{0}:47989/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&serverchallengeresp={3}",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        Guid.NewGuid(),
                        BytesToHex(encryptedChallengeResponse));
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
                {
                    using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                    {
                        outputTextBox.Text = $"Send challenge response status code: {response.StatusCode}\n";
                        string responseContent = await response.Content.ReadAsStringAsync();

                        outputTextBox.Text += responseContent + "\n";
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize((await response.Content.ReadAsInputStreamAsync()).AsStreamForRead()) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || !pairResponse.Paired)
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair here by calling http://<blah>/unpair?uniqueid={1}&uuid={2}.
                return;
            }

            // Get the server's signed secret.
            byte[] serverSecretResponse = HexToBytes(pairResponse.PairingSecret);
            byte[] serverSecret = new byte[16];
            byte[] serverSignature = new byte[256];
            Array.Copy(serverSecretResponse, 0, serverSecret, 0, serverSecret.Length);
            Array.Copy(serverSecretResponse, serverSecret.Length, serverSignature, 0, serverSignature.Length);

            if (!VerifySIgnature(serverSecret, serverSignature, serverCertificate))
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair as above.
                return;
            }
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

        private static byte[] ConcatenateByteArrays(params byte[][] byteArrays)
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

        private static byte[] HashData(IDigest hashAlgorithm, byte[] data)
        {
            byte[] hashedData = new byte[hashAlgorithm.GetDigestSize()];
            hashAlgorithm.BlockUpdate(data, 0, data.Length);
            hashAlgorithm.DoFinal(hashedData, 0);

            return hashedData;
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

        private static bool VerifySIgnature(byte[] data, byte[] signature, X509Certificate certificate)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(false, certificate.GetPublicKey());
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(signature);
        }

        private byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.secureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
