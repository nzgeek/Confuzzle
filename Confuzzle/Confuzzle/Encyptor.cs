/*
 * This work (Modern Encryption of a String C#, by James Tuley), 
 * identified by James Tuley, is free of known copyright restrictions.
 * https://gist.github.com/4336842
 * http://creativecommons.org/publicdomain/mark/1.0/ 
 */

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Confuzzle
{
    public static class Encryptor
    {
        private static readonly SecureRandom Random = new SecureRandom();

        //Preconfigured Encryption Parameters
        public static readonly int NonceBitSize = 128;
        public static readonly int MacBitSize = 128;
        public static readonly int KeyBitSize = 256;

        //Preconfigured Password Key Derivation Parameters
        public static readonly int SaltBitSize = 128;
        public static readonly int Iterations = 10000;
        public static readonly int MinPasswordLength = 12;


        /// <summary>
        ///     Helper that generates a random new key on each call.
        /// </summary>
        /// <returns></returns>
        public static byte[] NewKey()
        {
            var key = new byte[KeyBitSize/8];
            Random.NextBytes(key);
            return key;
        }

        /// <summary>
        ///     Simple Encryption And Authentication (AES-GCM) of a UTF8 string.
        /// </summary>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayload">Optional non-secret payload.</param>
        /// <returns>
        ///     Encrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">Secret Message Required!;secretMessage</exception>
        /// <remarks>
        ///     Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64
        /// </remarks>
        public static string SimpleEncrypt(string secretMessage, byte[] key, byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
                throw new ArgumentException("Secret Message Required!", nameof(secretMessage));

            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncrypt(plainText, key, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }


        /// <summary>
        ///     Simple Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayloadLength">Length of the optional non-secret payload.</param>
        /// <returns>Decrypted Message</returns>
        public static string SimpleDecrypt(string encryptedMessage, byte[] key, int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));

            var cipherText = Convert.FromBase64String(encryptedMessage);
            var plainText = SimpleDecrypt(cipherText, key, nonSecretPayloadLength);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }

        /// <summary>
        ///     Simple Encryption And Authentication (AES-GCM) of a UTF8 String
        ///     using key derived from a password (PBKDF2).
        /// </summary>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayload">The non secret payload.</param>
        /// <returns>
        ///     Encrypted Message
        /// </returns>
        /// <remarks>
        ///     Significantly less secure than using random binary keys.
        ///     Adds additional non secret payload for key generation parameters.
        /// </remarks>
        public static string SimpleEncryptWithPassword(string secretMessage, string password, byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
                throw new ArgumentException("Secret Message Required!", nameof(secretMessage));

            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncryptWithPassword(plainText, password, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }


        /// <summary>
        ///     Simple Decryption and Authentication (AES-GCM) of a UTF8 message
        ///     using a key derived from a password (PBKDF2)
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
        /// <returns>
        ///     Decrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage</exception>
        /// <remarks>
        ///     Significantly less secure than using random binary keys.
        /// </remarks>
        public static string SimpleDecryptWithPassword(string encryptedMessage, string password, int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrWhiteSpace(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));

            var cipherText = Convert.FromBase64String(encryptedMessage);
            var plainText = SimpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }


        /// <summary>
        ///     Simple Encryption And Authentication (AES-GCM) of a UTF8 string.
        /// </summary>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayload">Optional non-secret payload.</param>
        /// <returns>Encrypted Message</returns>
        /// <remarks>
        ///     Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64
        /// </remarks>
        public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] key, byte[] nonSecretPayload = null)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize/8)
                throw new ArgumentException($"Key needs to be {KeyBitSize} bit!", nameof(key));

            if (secretMessage == null || secretMessage.Length == 0)
                throw new ArgumentException("Secret Message Required!", nameof(secretMessage));

            //Non-secret Payload Optional
            nonSecretPayload = nonSecretPayload ?? new byte[] {};

            //Using random nonce large enough not to repeat
            var nonce = new byte[NonceBitSize/8];
            Random.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, nonSecretPayload);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
            var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        /// <summary>
        ///     Simple Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayloadLength">Length of the optional non-secret payload.</param>
        /// <returns>Decrypted Message</returns>
        public static byte[] SimpleDecrypt(byte[] encryptedMessage, byte[] key, int nonSecretPayloadLength = 0)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize/8)
                throw new ArgumentException($"Key needs to be {KeyBitSize} bit!", nameof(key));

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));

            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Payload
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);

                //Grab Nonce
                var nonce = cipherReader.ReadBytes(NonceBitSize/8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, nonSecretPayload);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonSecretPayloadLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    //Return null if it doesn't authenticate
                    return null;
                }

                return plainText;
            }
        }

        /// <summary>
        ///     Simple Encryption And Authentication (AES-GCM) of a UTF8 String
        ///     using key derived from a password.
        /// </summary>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayload">The non secret payload.</param>
        /// <returns>
        ///     Encrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">Must have a password of minimum length;password</exception>
        /// <remarks>
        ///     Significantly less secure than using random binary keys.
        ///     Adds additional non secret payload for key generation parameters.
        /// </remarks>
        public static byte[] SimpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
        {
            nonSecretPayload = nonSecretPayload ?? new byte[] {};

            //User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException($"Must have a password of at least {MinPasswordLength} characters!", nameof(password));

            if (secretMessage == null || secretMessage.Length == 0)
                throw new ArgumentException("Secret Message Required!", nameof(secretMessage));

            var generator = new Pkcs5S2ParametersGenerator();

            //Use Random Salt to minimize pre-generated weak password attacks.
            var salt = new byte[SaltBitSize/8];

            //Generate Key
            var key = GenerateKey(password, out salt);

            //Create Full Non Secret Payload
            var payload = new byte[salt.Length + nonSecretPayload.Length];
            Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
            Array.Copy(salt, 0, payload, nonSecretPayload.Length, salt.Length);

            return SimpleEncrypt(secretMessage, key.GetKey(), payload);
        }

        /// <summary>
        ///     Simple Decryption and Authentication of a UTF8 message
        ///     using a key derived from a password
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
        /// <returns>
        ///     Decrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">Must have a password of minimum length;password</exception>
        /// <remarks>
        ///     Significantly less secure than using random binary keys.
        /// </remarks>
        public static byte[] SimpleDecryptWithPassword(byte[] encryptedMessage, string password, int nonSecretPayloadLength = 0)
        {
            //User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException($"Must have a password of at least {MinPasswordLength} characters!", nameof(password));

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));

            var generator = new Pkcs5S2ParametersGenerator();

            //Grab Salt from Payload
            var salt = new byte[SaltBitSize/8];
            Array.Copy(encryptedMessage, nonSecretPayloadLength, salt, 0, salt.Length);

            //Generate Key
            var key = GenerateKey(password, salt);

            return SimpleDecrypt(encryptedMessage, key.GetKey(), salt.Length + nonSecretPayloadLength);
        }

        /// <summary>
        ///     Encrypts the contents from one stream to another stream, using the supplied password.
        /// </summary>
        /// <param name="inputStream">A stream containing cleartext to encrypt.</param>
        /// <param name="outputStream">A stream that will receive the ciphertext.</param>
        /// <param name="password">A password used to encrypt the cleartext.</param>
        public static void EncryptWithPassword(Stream inputStream, Stream outputStream, string password)
        {
            // Parameter validation
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("A readable input stream is required.", nameof(inputStream));

            if (outputStream == null || !outputStream.CanWrite)
                throw new ArgumentException("A writable output stream is required.", nameof(outputStream));

            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException($"Must have a password of at least {MinPasswordLength} characters!", nameof(password));

            // Generate the key with a random salt.
            byte[] salt;
            var key = GenerateKey(password, out salt);

            // Generate a random nonce to ensure multiple copies of the file encrypt differently
            var nonce = new byte[NonceBitSize / 8];
            Random.NextBytes(nonce, 0, nonce.Length);

            // Initialize the cipher
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(key, MacBitSize, nonce, salt);
            cipher.Init(true, parameters);

            // Write the salt and nonce
            outputStream.Write(salt, 0, salt.Length);
            outputStream.Write(nonce, 0, nonce.Length);

            // Prepare to copy the data
            int inputBytes, outputBytes;
            var inputBlock = new byte[cipher.GetBlockSize() * 64];
            var outputBlock = new byte[cipher.GetBlockSize() * 64];

            // Encrypt all data in the input stream
            while ((inputBytes = inputStream.Read(inputBlock, 0, inputBlock.Length)) > 0)
            {
                outputBytes = cipher.ProcessBytes(inputBlock, 0, inputBytes, outputBlock, 0);
                outputStream.Write(outputBlock, 0, outputBytes);
            }

            // Finalize the encrypted data
            outputBytes = cipher.DoFinal(outputBlock, 0);
            if (outputBytes > 0)
                outputStream.Write(outputBlock, 0, outputBytes);

            // Flush the output
            outputStream.Flush();
        }

        /// <summary>
        ///     Decrypts the contents from one stream to another stream, using the supplied password.
        /// </summary>
        /// <param name="inputStream">A stream containing ciphertext to decrypt.</param>
        /// <param name="outputStream">A stream that will receive the cleartext.</param>
        /// <param name="password">A password used to decrypt the ciphertext.</param>
        public static void DecryptWithPassword(Stream inputStream, Stream outputStream, string password)
        {
            // Parameter validation
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("A readable input stream is required.", nameof(inputStream));

            if (outputStream == null || !outputStream.CanWrite)
                throw new ArgumentException("A writable output stream is required.", nameof(outputStream));

            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException($"Must have a password of at least {MinPasswordLength} characters!", nameof(password));

            // Read the salt from the file
            var salt = new byte[SaltBitSize/8];
            if (inputStream.Read(salt, 0, salt.Length) != salt.Length)
                throw new InvalidDataException("Encrypted data missing password salt.");

            // Read the nonce from the file
            var nonce = new byte[NonceBitSize / 8];
            if (inputStream.Read(nonce, 0, nonce.Length) != nonce.Length)
                throw new InvalidDataException("Encrypted data missing password nonce.");

            // Generate the key with the saved salt
            var key = GenerateKey(password, salt);

            // Initialize the cipher
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(key, MacBitSize, nonce, salt);
            cipher.Init(false , parameters);

            // Prepare to copy the data
            int inputBytes, outputBytes;
            var inputBlock = new byte[cipher.GetBlockSize() * 64];
            var outputBlock = new byte[cipher.GetBlockSize() * 64];

            // Encrypt all data in the input stream
            while ((inputBytes = inputStream.Read(inputBlock, 0, inputBlock.Length)) > 0)
            {
                outputBytes = cipher.ProcessBytes(inputBlock, 0, inputBytes, outputBlock, 0);
                outputStream.Write(outputBlock, 0, outputBytes);
            }

            // Finalize the encrypted data
            outputBytes = cipher.DoFinal(outputBlock, 0);
            if (outputBytes > 0)
                outputStream.Write(outputBlock, 0, outputBytes);

            // Flush the output
            outputStream.Flush();
        }

        /// <summary>
        ///     Generates a cipher key using a new, random salt.
        /// </summary>
        /// <param name="password">A password that will be converted to a cipher key.</param>
        /// <param name="salt">Receives the generated salt.</param>
        /// <returns>Returns a <see cref="KeyParameter"/> containing the cipher key.</returns>
        private static KeyParameter GenerateKey(string password, out byte[] salt)
        {
            salt = new byte[SaltBitSize / 8];
            Random.NextBytes(salt);

            return GenerateKey(password, salt);
        }

        /// <summary>
        ///     Generates a cipher key using the specified salt.
        /// </summary>
        /// <param name="password">A password that will be converted to a cipher key.</param>
        /// <param name="salt">A salt used to convert the password.</param>
        /// <returns>Returns a <see cref="KeyParameter"/> containing the cipher key.</returns>
        private static KeyParameter GenerateKey(string password, byte[] salt)
        {
            var generator = new Pkcs5S2ParametersGenerator();
            generator.Init(
                PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()),
                salt,
                Iterations);

            return (KeyParameter)generator.GenerateDerivedMacParameters(KeyBitSize);
        }
    }
}