using Mono.Security;
using Mono.Security.X509;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Anomalous.Security
{
    public class CertificateStore
    {
        private const String hashAlgoName = "SHA256";
        private static readonly String hashAlgoId = CryptoConfig.MapNameToOID(hashAlgoName);

        public CertificateStore()
        {
            TrustAnchors = new X509CertificateCollection();
            ValidDllCertificates = new X509CertificateCollection();
            DataFileCounterSignatureCAs = new CertificateAuthorityInfo();
            DataFileSignatureCAs = new CertificateAuthorityInfo();
            IssueDate = DateTime.UtcNow;
        }

        public CertificateStore(ASN1 asn1)
        {
            IssueDate = ASN1Convert.ToDateTime(asn1[0]);
            TrustAnchors = CryptoHelper.readCertificates(asn1.Element(1, 0x30));
            ValidDllCertificates = CryptoHelper.readCertificates(asn1.Element(2, 0x30));
            DataFileCounterSignatureCAs = new CertificateAuthorityInfo(asn1.Element(3, 0x30));
            DataFileSignatureCAs = new CertificateAuthorityInfo(asn1.Element(4, 0x30));
            ASN1 serverCommunicationInfo = asn1[5];
            if (serverCommunicationInfo.Length != 0)
            {
                ServerCommunicationCertificate = new X509Certificate(serverCommunicationInfo[0].GetBytes());
                ServerCommunicationHashAlgo = Encoding.UTF8.GetString(serverCommunicationInfo[1].Value);
            }
        }

        public DateTime IssueDate { get; set; }

        public X509CertificateCollection TrustAnchors { get; private set; }

        public X509CertificateCollection ValidDllCertificates { get; private set; }

        public CertificateAuthorityInfo DataFileCounterSignatureCAs { get; set; }

        public CertificateAuthorityInfo DataFileSignatureCAs { get; set; }

        public X509Certificate ServerCommunicationCertificate { get; set; }

        public String ServerCommunicationHashAlgo { get; set; }

        public void setupChain(X509Chain chain)
        {
            chain.TrustAnchors.AddRange(TrustAnchors);
        }

        public ASN1 asASN1()
        {
            ASN1 data = new ASN1(0x30);

            data.Add(ASN1Convert.FromDateTime(IssueDate));
            data.Add(CryptoHelper.writeCertificates(TrustAnchors));
            data.Add(CryptoHelper.writeCertificates(ValidDllCertificates));
            data.Add(DataFileCounterSignatureCAs.GetData());
            data.Add(DataFileSignatureCAs.GetData());
            if (ServerCommunicationCertificate != null)
            {
                if (ServerCommunicationHashAlgo == null)
                {
                    throw new Exception("Must specify a hash algorithm for the server communications if a cert is specified.");
                }
                ASN1 serverCommunicationInfo = new ASN1(0x30);
                serverCommunicationInfo.Add(new ASN1(ServerCommunicationCertificate.RawData));
                serverCommunicationInfo.Add(new ASN1(0x13, Encoding.UTF8.GetBytes(ServerCommunicationHashAlgo)));
                data.Add(serverCommunicationInfo);
            }
            else
            {
                data.Add(new ASN1(0x30));
            }
            
            return data;
        }

        public byte[] getSignedBytes(PKCS12 signingCert)
        {
            RSACryptoServiceProvider privateKey = CryptoHelper.findPrivateKey(signingCert);

            ASN1 data = asASN1();
            
            //Signature section
            using (HashAlgorithm hashAlgo = HashAlgorithm.Create(hashAlgoName))
            {
                byte[] hash = hashAlgo.ComputeHash(data.Value);
                byte[] signature = privateKey.SignHash(hash, hashAlgoId);
                ASN1 signatureData = new ASN1(0x30);
                signatureData.Add(new ASN1(0x13, signature)); //Signature, bit string
                ASN1 certificates = new ASN1(0x30); //Certificate sequence
                foreach (var cert in signingCert.Certificates) //All certificates for this file
                {
                    certificates.Add(new ASN1(cert.RawData));
                }
                signatureData.Add(certificates);

                //Main Collection
                ASN1 asn1 = new ASN1(0x30);
                asn1.Add(data);
                asn1.Add(signatureData);
                return asn1.GetBytes();
            }
        }

        public static CertificateStore fromSignedBytes(byte[] bytes, X509Certificate trustRoot, X509Certificate trustedSignature)
        {
            ASN1 asn1 = new ASN1(bytes);
            
            ASN1 signatureData = asn1.Element(1, 0x30);

            X509Chain chain = new X509Chain();
            chain.TrustAnchors.Add(trustRoot);
            ASN1 certificates = signatureData.Element(1, 0x30);
            X509Certificate lastCert = null;
            for (int i = certificates.Count - 1; i >= 0; --i)
            {
                lastCert = new X509Certificate(certificates[i].GetBytes());
                chain.LoadCertificate(lastCert);
            }
            if (!chain.Build(lastCert))
            {
                throw new SigningException(String.Format("Invalid Chain. Reason '{0}'.", chain.Status));
            }

            if (!CryptoHelper.Compare(trustedSignature.SerialNumber, lastCert.SerialNumber))
            {
                throw new SigningException("Certificate Store not signed by trusted signature.");
            }

            if (!lastCert.IsCurrent)
            {
                throw new SigningException("The Certificate Store has expired");
            }

            ASN1 data = asn1.Element(0, 0x30);
            using (HashAlgorithm hashAlgo = HashAlgorithm.Create(hashAlgoName))
            {
                byte[] hash = hashAlgo.ComputeHash(data.Value);
                byte[] signature = signatureData.Element(0, 0x13).Value;

                if (lastCert.CheckSignature(hash, hashAlgoId, signature))
                {
                    return new CertificateStore(data);
                }
                else
                {
                    throw new SigningException("Invalid Signature.");
                }
            }
        }
    }
}
