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
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.X509;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Certificates;
    using Windows.UI.Xaml.Controls;
    using Windows.Web.Http;
    using Windows.Web.Http.Filters;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class WindowsWebHttpClientPairingManager : PairingManager
    {
        public override async Task PairAsync(string ipAddress, TextBox outputTextBox)
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
            keyPairGenerator.Init(new KeyGenerationParameters(this.SecureRandom, 2048));
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
                store.Save(memoryStream, password.ToCharArray(), this.SecureRandom);
                pfxData = CryptographicBuffer.EncodeToBase64String(memoryStream.ToArray().AsBuffer());
            }

            await CertificateEnrollmentManager.ImportPfxDataAsync(
                pfxData,
                password,
                ExportOption.NotExportable,
                KeyProtectionLevel.NoConsent,
                InstallOptions.DeleteExpired,
                friendlyName);

            // Read the UWP cert from the cert store
            Certificate uwpCertificate =
                (await CertificateStores.FindAllAsync(
                    new CertificateQuery { FriendlyName = friendlyName }))[0];

            string keyString;
            using (StringWriter keyWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(keyWriter);
                pemWriter.WriteObject(keyPair);
                keyString = keyWriter.ToString();

                // Line endings must be UNIX style for GFE to accept the certificate.
                keyString = keyString.Replace(Environment.NewLine, "\n");
            }

            string certString;
            using (StringWriter certWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(certWriter);
                pemWriter.WriteObject(certificate);
                certString = certWriter.ToString();

                // Line endings must be UNIX style for GFE to accept the certificate.
                certString = certString.Replace(Environment.NewLine, "\n");
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
                    ipAddress,
                    BytesToHex(uniqueId),
                    Guid.NewGuid().ToString("N"));
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
                    "http://{0}:47989/pair?uniqueid={1}&uuid={2}&devicename=roth&updateState=1&phrase=getservercert&salt={3}&clientcert={4}",
                    ipAddress,
                    BytesToHex(uniqueId),
                    Guid.NewGuid().ToString("N"),
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
                        ipAddress,
                        BytesToHex(uniqueId),
                        Guid.NewGuid().ToString("N"),
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
                        ipAddress,
                        BytesToHex(uniqueId),
                        Guid.NewGuid().ToString("N"),
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
                        ipAddress,
                        BytesToHex(uniqueId),
                        Guid.NewGuid().ToString("N"),
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
                        ipAddress,
                        BytesToHex(uniqueId),
                        Guid.NewGuid().ToString("N"));
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

            await Task.Delay(2000);

            outputTextBox.Text = "Pairing succeeded!\n";
        }
    }
}
