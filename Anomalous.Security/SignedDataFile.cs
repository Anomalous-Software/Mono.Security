﻿using Mono.Security;
using Mono.Security.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Anomalous.Security
{
    public class SignedDataFile
    {
        public enum TrustedResult
        {
            Valid,
            InvalidSignature,
            InvalidChain,
            InvalidChainCA,
            SignatureCertRevoked,
            TimestampOutsideRange,
            NotSigned,
            FileNotFound,
            UnspecifiedError,
            InvalidCounterSignature,
            InvalidCounterSignatureChain,
            InvalidCounterSignatureChainCA,
            CounterSignatureCertRevoked,
        }

        private static readonly byte[] SignatureMagicString = new byte[] { 65, 78, 79, 77, 83, 73, 71 }; //ANOMSIG magic string
        private static readonly long MagicStringSize = sizeof(byte) * SignatureMagicString.Length;
        private static readonly long FooterStartPosition = MagicStringSize + sizeof(long);

        private const String hashAlgoName = "SHA256";
        private static readonly String hashAlgoId = CryptoConfig.MapNameToOID(hashAlgoName);

        public static void SignDataFile(String file, String outFile, PKCS12 signingCert, PKCS12 counterSignatureCert)
        {
            using (Stream sourceStream = File.Open(file, FileMode.Open, FileAccess.Read))
            {
                using (Stream destStream = File.Open(outFile, FileMode.Create, FileAccess.Write))
                {
                    SignDataFile(sourceStream, destStream, signingCert, counterSignatureCert);
                }
            }
        }

        public static void SignDataFile(Stream source, Stream destination, PKCS12 signingCert, PKCS12 counterSignatureCert)
        {
            RSACryptoServiceProvider signingPrivateKey = CryptoHelper.findPrivateKey(signingCert);
            RSACryptoServiceProvider counterPrivateKey = CryptoHelper.findPrivateKey(counterSignatureCert);
            SignDataFile(source, destination, signingPrivateKey, signingCert.Certificates[0].RawData, counterPrivateKey, counterSignatureCert.Certificates[0].RawData);
        }

        public static void SignDataFile(Stream source, Stream destination, RSACryptoServiceProvider signingPrivateKey, byte[] signingCertBytes, RSACryptoServiceProvider counterPrivateKey, byte[] counterSigningCertBytes)
        {
            using (BinaryReader br = new BinaryReader(source))
            {
                if (hasSignature(br))
                {
                    long footerStart = findFooterStart(br);
                    br.BaseStream.Seek(0, SeekOrigin.Begin);
                    Stream signedStream = new SignedStream(br.BaseStream, footerStart);
                    createSignature(destination, signedStream, signingPrivateKey, signingCertBytes, counterPrivateKey, counterSigningCertBytes);
                }
                else
                {
                    br.BaseStream.Seek(0, SeekOrigin.Begin);
                    createSignature(destination, br.BaseStream, signingPrivateKey, signingCertBytes, counterPrivateKey, counterSigningCertBytes);
                }
            }
        }

        private static void createSignature(Stream destinationStream, Stream stream, RSACryptoServiceProvider signingPrivateKey, byte[] signingCertBytes, RSACryptoServiceProvider counterPrivateKey, byte[] counterSigningCertBytes)
        {
            //Convert to / from asn1 so that the timestamp we hash with matches what will
            //be decoded when we check the signature, by default there are extra ticks likley
            //for sub seconds.
            ASN1 timestampAsn1 = ASN1Convert.FromDateTime(DateTime.UtcNow);
            DateTime timestamp = ASN1Convert.ToDateTime(timestampAsn1);

            byte[] hash, signature, counterHash, counterSignature;
            using (HashAlgorithm hashAlgo = HashAlgorithm.Create(hashAlgoName))
            {
                //Compute file hash
                try
                {
                    hash = hashAlgo.ComputeHash(stream);
                    signature = signingPrivateKey.SignHash(hash, hashAlgoId);
                }
                catch(CryptographicException ex)
                {
                    throw new SigningException(String.Format("Signature threw CryptographicException. Inner Message: {0}", ex.Message));
                }

                try
                {
                    counterHash = CryptoHelper.computeCounterHash(hashAlgo, hash, timestamp.Ticks);
                    counterSignature = counterPrivateKey.SignHash(counterHash, hashAlgoId);
                }
                catch (CryptographicException ex)
                {
                    throw new SigningException(String.Format("Counter Signature threw CryptographicException. Inner Message: {0}", ex.Message));
                }
            }

            stream.Seek(0, SeekOrigin.Begin);
            using (BinaryWriter outStream = new BinaryWriter(destinationStream))
            {
                stream.CopyTo(outStream.BaseStream);
                long footerStart = stream.Position;

                ASN1 signatureData = new ASN1(0x30);
                signatureData.Add(new ASN1(0x13, signature)); //Signature, bit string
                signatureData.Add(new ASN1(signingCertBytes));

                ASN1 counterSignatureData = new ASN1(0x30);
                counterSignatureData.Add(new ASN1(0x13, counterSignature)); //Counter signature, bit string
                counterSignatureData.Add(timestampAsn1); //Timestamp
                counterSignatureData.Add(new ASN1(counterSigningCertBytes));

                ASN1 footerData = new ASN1(0x30);
                footerData.Add(signatureData);
                footerData.Add(counterSignatureData);
                outStream.Write(footerData.GetBytes());
                outStream.Write(footerStart);
                outStream.Write(SignatureMagicString);
            }
        }

        private CertificateStore certificateStore;

        public SignedDataFile(CertificateStore certificateStore)
        {
            this.certificateStore = certificateStore;
        }

        public TrustedResult isTrustedFile(String file)
        {
            reset();
            try
            {
                byte[] signature, counterSignature;
                using (BinaryReader reader = new BinaryReader(File.OpenRead(file)))
                {
                    if (!hasSignature(reader))
                    {
                        return TrustedResult.NotSigned;
                    }
                    long footerStart = findFooterStart(reader);
                    reader.BaseStream.Seek(footerStart, SeekOrigin.Begin);
                    int ans1Length = (int)(reader.BaseStream.Length - FooterStartPosition - footerStart);
                    ASN1 footerData = new ASN1(reader.ReadBytes(ans1Length));

                    ASN1 signatureData = footerData[0];
                    signature = signatureData.Element(0, 0x13).Value;
                    Certificate = new X509Certificate(signatureData[1].GetBytes());

                    ASN1 counterSignatureData = footerData[1];
                    counterSignature = counterSignatureData.Element(0, 0x13).Value;
                    Timestamp = ASN1Convert.ToDateTime(counterSignatureData[1]);
                    CounterSignatureCertificate = new X509Certificate(counterSignatureData[2].GetBytes());

                    if (Timestamp < Certificate.ValidFrom || Timestamp > Certificate.ValidUntil)
                    {
                        return TrustedResult.TimestampOutsideRange;
                    }

                    Chain = new X509Chain();
                    Chain.LoadCertificate(Certificate);
                    Chain.LoadCertificates(certificateStore.DataFileSignatureCAs.Certificates);
                    Chain.LoadCertificates(certificateStore.TrustAnchors);
                    Chain.TrustAnchors.AddRange(certificateStore.TrustAnchors);
                    if (!Chain.Build(Certificate, Timestamp))
                    {
                        return TrustedResult.InvalidChain;
                    }

                    X509Certificate signatureAuthorityCert = certificateStore.DataFileSignatureCAs.FindAuthorityCert(Chain);
                    if (signatureAuthorityCert == null)
                    {
                        return TrustedResult.InvalidChainCA;
                    }
                        
                    if (certificateStore.DataFileSignatureCAs.IsRevoked(Timestamp, Certificate, signatureAuthorityCert))
                    {
                        return TrustedResult.SignatureCertRevoked;
                    }

                    reader.BaseStream.Seek(0, SeekOrigin.Begin);
                    byte[] hash;
                    using (HashAlgorithm hashAlgo = HashAlgorithm.Create(hashAlgoName))
                    {
                        using (Stream stream = new SignedStream(reader.BaseStream, footerStart))
                        {
                            //Compute file hash
                            hash = hashAlgo.ComputeHash(stream);
                        }
                        if (!Certificate.CheckSignature(hash, hashAlgoId, signature))
                        {
                            return TrustedResult.InvalidSignature;
                        }

                        CounterSignatureChain = new X509Chain();
                        CounterSignatureChain.LoadCertificate(CounterSignatureCertificate);
                        CounterSignatureChain.LoadCertificates(certificateStore.DataFileCounterSignatureCAs.Certificates);
                        CounterSignatureChain.LoadCertificates(certificateStore.TrustAnchors);
                        CounterSignatureChain.TrustAnchors.AddRange(certificateStore.TrustAnchors);
                        if (!CounterSignatureChain.Build(CounterSignatureCertificate, Timestamp))
                        {
                            return TrustedResult.InvalidCounterSignatureChain;
                        }

                        X509Certificate counterSignatureAuthorityCert = certificateStore.DataFileCounterSignatureCAs.FindAuthorityCert(CounterSignatureChain);
                        if (counterSignatureAuthorityCert == null)
                        {
                            return TrustedResult.InvalidCounterSignatureChainCA;
                        }

                        if (certificateStore.DataFileCounterSignatureCAs.IsRevoked(Timestamp, CounterSignatureCertificate, counterSignatureAuthorityCert))
                        {
                            return TrustedResult.CounterSignatureCertRevoked;
                        }

                        byte[] counterHash = CryptoHelper.computeCounterHash(hashAlgo, hash, Timestamp.Ticks);
                        if (CounterSignatureCertificate.CheckSignature(counterHash, hashAlgoId, counterSignature))
                        {
                            return TrustedResult.Valid;
                        }
                        else
                        {
                            return TrustedResult.InvalidCounterSignature;
                        }
                    }
                }
            }
            catch (FileNotFoundException)
            {
                return TrustedResult.FileNotFound;
            }
            catch (Exception ex)
            {
                UnspecifiedErrorMessage = String.Format("{0} Exception. Reason: {1}", ex.GetType().Name, ex.Message);
                return TrustedResult.UnspecifiedError;
            }
        }

        public String UnspecifiedErrorMessage { get; private set; }

        public X509Chain Chain { get; private set; }

        public X509Chain CounterSignatureChain { get; private set; }

        public DateTime Timestamp { get; private set; }

        public X509Certificate Certificate { get; private set; }

        public X509Certificate CounterSignatureCertificate { get; set; }

        private static bool hasSignature(BinaryReader reader)
        {
            reader.BaseStream.Seek(-MagicStringSize, SeekOrigin.End);
            byte[] magicString = reader.ReadBytes(SignatureMagicString.Length);
            bool hasSignature = CryptoHelper.Compare(SignatureMagicString, magicString);
            return hasSignature;
        }

        private static long findFooterStart(BinaryReader reader)
        {
            reader.BaseStream.Seek(-FooterStartPosition, SeekOrigin.End);
            long footerStart = reader.ReadInt64();
            return footerStart;
        }

        private void reset()
        {
            UnspecifiedErrorMessage = null;
            Chain = null;
            Certificate = null;
            CounterSignatureChain = null;
            CounterSignatureCertificate = null;
            Timestamp = DateTime.MinValue;
        }
    }
}
