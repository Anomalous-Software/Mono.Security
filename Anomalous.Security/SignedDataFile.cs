using Mono.Security;
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

        public static void SignDataFile(String file, String outFile, PKCS12 signingCert, PKCS12 timestampCert)
        {
            using (BinaryReader br = new BinaryReader(File.Open(file, FileMode.Open, FileAccess.Read)))
            {
                if (hasSignature(br))
                {
                    long footerStart = findFooterStart(br);
                    br.BaseStream.Seek(0, SeekOrigin.Begin);
                    Stream signedStream = new SignedStream(br.BaseStream, footerStart);
                    createSignature(outFile, signedStream, signingCert, timestampCert);
                }
                else
                {
                    br.BaseStream.Seek(0, SeekOrigin.Begin);
                    createSignature(outFile, br.BaseStream, signingCert, timestampCert);
                }
            }
        }

        private static void createSignature(String outFile, Stream stream, PKCS12 signingCert, PKCS12 counterSigningCert)
        {
            RSACryptoServiceProvider signingPrivateKey = CryptoHelper.findPrivateKey(signingCert);
            RSACryptoServiceProvider counterPrivateKey = CryptoHelper.findPrivateKey(counterSigningCert);
            //Convert to / from asn1 so that the timestamp we hash with matches what will
            //be decoded when we check the signature, by default there are extra ticks likley
            //for sub seconds.
            ASN1 timestampAsn1 = ASN1Convert.FromDateTime(DateTime.UtcNow);
            DateTime timestamp = ASN1Convert.ToDateTime(timestampAsn1);

            byte[] hash, signature, counterHash, counterSignature;
            using (HashAlgorithm hashAlgo = HashAlgorithm.Create(hashAlgoName))
            {
                //Compute file hash
                hash = hashAlgo.ComputeHash(stream);
                signature = signingPrivateKey.SignHash(hash, hashAlgoId);
                counterHash = CryptoHelper.computeCounterHash(hashAlgo, hash, timestamp.Ticks);
                counterSignature = counterPrivateKey.SignHash(counterHash, hashAlgoId);
            }

            stream.Seek(0, SeekOrigin.Begin);
            using (BinaryWriter outStream = new BinaryWriter(File.Open(outFile, FileMode.Create, FileAccess.Write)))
            {
                stream.CopyTo(outStream.BaseStream);
                long footerStart = stream.Position;

                ASN1 signatureData = new ASN1(0x30);
                signatureData.Add(new ASN1(0x13, signature)); //Signature, bit string
                signatureData.Add(CryptoHelper.writeCertificates(signingCert.Certificates));

                ASN1 counterSignatureData = new ASN1(0x30);
                counterSignatureData.Add(new ASN1(0x13, counterSignature)); //Counter signature, bit string
                counterSignatureData.Add(timestampAsn1); //Timestamp
                counterSignatureData.Add(CryptoHelper.writeCertificates(counterSigningCert.Certificates));

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
                using (BinaryReader reader = new BinaryReader(File.Open(file, FileMode.Open, FileAccess.Read)))
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
                    X509CertificateCollection signingCertificates = CryptoHelper.readCertificates(signatureData.Element(1, 0x30));
                    Certificate = signingCertificates[0];

                    ASN1 counterSignatureData = footerData[1];
                    counterSignature = counterSignatureData.Element(0, 0x13).Value;
                    Timestamp = ASN1Convert.ToDateTime(counterSignatureData[1]);
                    X509CertificateCollection counterSignatureCertificates = CryptoHelper.readCertificates(counterSignatureData.Element(2, 0x30));
                    CounterSignatureCertificate = counterSignatureCertificates[0];

                    if (Timestamp < Certificate.ValidFrom || Timestamp > Certificate.ValidUntil)
                    {
                        return TrustedResult.TimestampOutsideRange;
                    }

                    Chain = new X509Chain();
                    Chain.LoadCertificates(signingCertificates);
                    certificateStore.setupChain(Chain);
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
                        CounterSignatureChain.LoadCertificates(counterSignatureCertificates);
                        certificateStore.setupChain(CounterSignatureChain);
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
