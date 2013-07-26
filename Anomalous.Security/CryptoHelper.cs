using Mono.Security;
using Mono.Security.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Anomalous.Security
{
    public class CryptoHelper
    {
        public static PKCS12 LoadPkcs12(String filename, String password)
        {
            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] rawBytes = new byte[fs.Length];
                fs.Read(rawBytes, 0, rawBytes.Length);
                fs.Close();
                return new PKCS12(rawBytes, password);
            }
        }

        public static X509Certificate LoadCertificate(string filename)
        {
            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] rawcert = new byte[fs.Length];
                fs.Read(rawcert, 0, rawcert.Length);
                fs.Close();
                return new X509Certificate(rawcert);
            }
        }

        public static byte[] computeCounterHash(HashAlgorithm hashAlgo, byte[] hash, long timestamp)
        {
            //Append timestamp to file hash
            byte[] timestampHash = new byte[hash.Length + sizeof(long)];
            Buffer.BlockCopy(hash, 0, timestampHash, 0, hash.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, timestampHash, hash.Length, sizeof(long));

            //Compute hash of hash + timestamp
            return hashAlgo.ComputeHash(timestampHash);
        }

        public static RSACryptoServiceProvider findPrivateKey(PKCS12 pkcs12)
        {
            if (pkcs12.Keys.Count < 0)
            {
                throw new SigningException("No keys found.");
            }
            RSACryptoServiceProvider privateKey = pkcs12.Keys[0] as RSACryptoServiceProvider;
            if (privateKey == null)
            {
                throw new SigningException("First key is not a RSACryptoServiceProvider");
            }
            if (privateKey.PublicOnly)
            {
                throw new SigningException("Key is only public");
            }
            return privateKey;
        }

        public static ASN1 writeCertificates(X509CertificateCollection certificates)
        {
            ASN1 asn1 = new ASN1(0x30); //Certificate sequence
            foreach (var cert in certificates) //All certificates for this file
            {
                asn1.Add(new ASN1(cert.RawData));
            }
            return asn1;
        }

        public static ASN1 writeCertificatesFromBytes(IEnumerable<byte[]> certificates)
        {
            ASN1 asn1 = new ASN1(0x30); //Certificate sequence
            foreach (var cert in certificates) //All certificates for this file
            {
                asn1.Add(new ASN1(cert));
            }
            return asn1;
        }

        public static IEnumerable<byte[]> getCertBytesFromCollection(X509CertificateCollection collection)
        {
            foreach (var cert in collection)
            {
                yield return cert.RawData;
            }
        }

        public static X509CertificateCollection readCertificates(ASN1 certificates)
        {
            X509CertificateCollection collection = new X509CertificateCollection();
            for (int i = 0; i < certificates.Count; ++i)
            {
                collection.Add(new X509Certificate(certificates[i].GetBytes()));
            }
            return collection;
        }

        public static bool Compare(byte[] array1, byte[] array2)
        {
            if ((array1 == null) && (array2 == null))
                return true;
            if ((array1 == null) || (array2 == null))
                return false;
            if (array1.Length != array2.Length)
                return false;
            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }
            return true;
        }
    }
}
