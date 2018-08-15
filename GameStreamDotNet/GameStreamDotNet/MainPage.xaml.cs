namespace GameStreamDotNet
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices.WindowsRuntime;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml.Serialization;

    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Certificates;
    using Windows.UI.Xaml;
    using Windows.UI.Xaml.Controls;
    using Windows.Web.Http;
    using Windows.Web.Http.Filters;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public sealed partial class MainPage : Page
    {
        private const string HexAlphabet = "0123456789ABCDEF";

        private static readonly int[] HexValues =
            new int[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        private readonly SecureRandom secureRandom;

        public MainPage()
        {
            this.InitializeComponent();
            this.secureRandom = new SecureRandom(new CryptoApiRandomGenerator());
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

            // Asymmetric key pair
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new KeyGenerationParameters(this.secureRandom, 2048));
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            // Certificate issuer and name
            X509Name name = new X509Name("CN=NVIDIA GameStream Client");

            // Certificate serial number
            byte[] serialBytes = this.GenerateRandomBytes(8);
            BigInteger serial = new BigInteger(serialBytes).Abs();

            // Expires in 20 years
            DateTime now = DateTime.UtcNow;
            DateTime expiration = now.AddYears(20);

            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSubjectDN(name);
            generator.SetIssuerDN(name);
            generator.SetSerialNumber(serial);
            generator.SetNotBefore(now);
            generator.SetNotAfter(expiration);
            generator.SetPublicKey(keyPair.Public);

            BouncyCastleX509Certificate certificate =
                generator.Generate(
                    new Asn1SignatureFactory("SHA1WithRSA", keyPair.Private));

            // Create PKCS12 certificate bytes.
            Pkcs12Store store = new Pkcs12Store();
            X509CertificateEntry certificateEntry = new X509CertificateEntry(certificate);
            string friendlyName = "Moonlight Xbox";
            string password = "password";
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(
                friendlyName,
                new AsymmetricKeyEntry(keyPair.Private),
                new X509CertificateEntry[] { certificateEntry });
            string pfxData;
            using (MemoryStream memoryStream = new MemoryStream(512))
            {
                store.Save(memoryStream, password.ToCharArray(), this.secureRandom);
                pfxData = CryptographicBuffer.EncodeToBase64String(memoryStream.ToArray().AsBuffer());
            }

            await CertificateEnrollmentManager.ImportPfxDataAsync(
                pfxData,
                password,
                ExportOption.NotExportable,
                KeyProtectionLevel.NoConsent,
                InstallOptions.DeleteExpired,
                friendlyName);

            // Read the modified cert from the cert store
            Certificate uwpCertificate =
                (await CertificateStores.FindAllAsync(
                    new CertificateQuery { FriendlyName = friendlyName }))[0];
            certificate = new X509CertificateParser().ReadCertificate(uwpCertificate.GetCertificateBlob().AsStream());

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

            // Create the HTTP client.
            HttpBaseProtocolFilter filter = new HttpBaseProtocolFilter();
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
            filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
            filter.ClientCertificate = uwpCertificate;

            HttpClient httpClient = new HttpClient(filter);

            // Unpair before doing anything else in this test app.
            string uriString =
                string.Format(
                    "http://{0}:47989/unpair?uniqueid={1}&uuid={2}",
                    ipAddressTextBox.Text,
                    BytesToHex(uniqueId),
                    Guid.NewGuid());
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
            {
                using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                {
                    outputTextBox.Text = $"Unpair status code: {response.StatusCode}\n";
                    string responseContent = await response.Content.ReadAsStringAsync();
                    outputTextBox.Text += responseContent + "\n";
                }
            }

            await Task.Delay(2000);

            outputTextBox.Text = $"Enter pin: {pin}";

            // Get server certificate.
            // TODO: Call should have no timeout because it requires the user to enter a pin.
            PairResponse pairResponse = null;
            uriString =
                string.Format(
                    "https://{0}:47984/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&phrase=getservercert&salt={3}&clientcert={4}",
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
                    outputTextBox.Text += responseContent + "\n";
                    using (StringReader reader = new StringReader(responseContent))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize(new StringReader(responseContent)) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || pairResponse.Paired != 1)
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
            BouncyCastleX509Certificate serverCertificate = new X509CertificateParser().ReadCertificate(serverCertBytes);

            // Hash the salt and pin and use it to generate an AES key. 
            byte[] hashedSaltAndPin = HashData(hashAlgorithm, saltAndPin);
            ICipherParameters aesKey = GenerateCipherKey(hashedSaltAndPin);

            // Generate a random challenge and encrypt it using AES.
            byte[] challenge = GenerateRandomBytes(16);
            byte[] encryptedChallenge = DoAesCipher(true, aesKey, challenge);

            await Task.Delay(2000);

            // Send the encrypted challenge to the server.
            // TODO: Call should have a timeout.
            uriString =
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
                    using (StringReader reader = new StringReader(responseContent))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize(new StringReader(responseContent)) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || pairResponse.Paired != 1)
            {
                outputTextBox.Text += "Pairing failed.\n";
                return;
            }

            // Decode the server's response and subsequent challenge.
            byte[] encryptedServerChallengeResponse = HexToBytes(pairResponse.ChallengeResponse);
            byte[] decryptedServerChallengeResponse = DoAesCipher(false, aesKey, encryptedServerChallengeResponse);

            byte[] serverResponse = new byte[hashDigestSize];
            byte[] serverChallenge = new byte[16];
            Array.Copy(decryptedServerChallengeResponse, serverResponse, hashDigestSize);
            Array.Copy(decryptedServerChallengeResponse, hashDigestSize, serverChallenge, 0, 16);

            // Using another 16 byte secret, compute a challenge response hash using the secret, 
            // our certificate signature, and the challenge.
            byte[] clientSecret = GenerateRandomBytes(16);
            byte[] challengeResponseHash =
                HashData(
                    hashAlgorithm,
                    ConcatenateByteArrays(serverChallenge, certificate.GetSignature(), clientSecret));
            byte[] encryptedChallengeResponse = DoAesCipher(true, aesKey, challengeResponseHash);

            await Task.Delay(2000);

            // Send the challenge response to the server.
            // TODO: Call should have a timeout.
            uriString =
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
                    using (StringReader reader = new StringReader(responseContent))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize(new StringReader(responseContent)) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || pairResponse.Paired != 1)
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair here by calling http://<blah>/unpair?uniqueid={1}&uuid={2}.
                return;
            }

            // Get the server's signed secret.
            byte[] serverSecretResponse = HexToBytes(pairResponse.PairingSecret);
            byte[] serverSecret = new byte[16];
            byte[] serverSignature = new byte[256];
            Array.Copy(serverSecretResponse, serverSecret, serverSecret.Length);
            Array.Copy(serverSecretResponse, serverSecret.Length, serverSignature, 0, serverSignature.Length);

            if (!VerifySignature(serverSecret, serverSignature, serverCertificate.GetPublicKey()))
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair as above.
                return;
            }

            // Ensure the server challenge matched what we expected (the PIN was correct).
            byte[] serverChallengeResponseHash =
                HashData(
                    hashAlgorithm,
                    ConcatenateByteArrays(
                        challenge,
                        serverCertificate.GetSignature(),
                        serverSecret));
            if (!serverChallengeResponseHash.SequenceEqual(serverResponse))
            {
                outputTextBox.Text += "Pairing failed due to wrong pin.\n";
                // TODO: Unpair as above.
                return;
            }

            await Task.Delay(2000);

            // Send the server our signed secret
            // TODO: Call should have a timeout.
            byte[] signedSecret = SignData(clientSecret, keyPair.Private);
            byte[] clientPairingSecret =
                ConcatenateByteArrays(
                    clientSecret,
                    signedSecret);
            uriString =
                    string.Format(
                        "http://{0}:47989/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&clientpairingsecret={3}",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        Guid.NewGuid(),
                        BytesToHex(clientPairingSecret));
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
            {
                using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                {
                    outputTextBox.Text = $"Send client pairing secret status code: {response.StatusCode}\n";
                    string responseContent = await response.Content.ReadAsStringAsync();
                    outputTextBox.Text += responseContent + "\n";
                    using (StringReader reader = new StringReader(responseContent))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize(new StringReader(responseContent)) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || pairResponse.Paired != 1)
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair as above.
                return;
            }

            await Task.Delay(2000);

            // Do the initial challenge (seems neccessary for us to show as paired).
            // TODO: Call should have a timeout.
            uriString =
                    string.Format(
                        "https://{0}:47984/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&phrase=pairchallenge",
                        ipAddressTextBox.Text,
                        BytesToHex(uniqueId),
                        Guid.NewGuid());
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri(uriString)))
            {
                using (HttpResponseMessage response = await httpClient.SendRequestAsync(request))
                {
                    outputTextBox.Text = $"Send pair challenge status code: {response.StatusCode}\n";
                    string responseContent = await response.Content.ReadAsStringAsync();
                    outputTextBox.Text += responseContent + "\n";
                    using (StringReader reader = new StringReader(responseContent))
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(PairResponse));
                        pairResponse = serializer.Deserialize(new StringReader(responseContent)) as PairResponse;
                    }
                }
            }

            if (pairResponse == null || pairResponse.Paired != 1)
            {
                outputTextBox.Text += "Pairing failed.\n";
                // TODO: Unpair as above.
                return;
            }

            outputTextBox.Text = "Pairing succeeded!\n";
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
                result.Append(HexAlphabet[b & 0x0F]);
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

        private static bool VerifySignature(byte[] data, byte[] signature, ICipherParameters key)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(false, key);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(signature);
        }


        private static byte[] SignData(byte[] data, ICipherParameters key)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, key);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        private byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.secureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
