using Mono.Security;
using Mono.Security.X509;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Anomalous.Security
{
    public class CertificateAuthorityInfo
    {
        private Dictionary<X509Certificate, X509Crl> certificates = new Dictionary<X509Certificate, X509Crl>();

        public CertificateAuthorityInfo()
        {

        }

        public CertificateAuthorityInfo(ASN1 data)
        {
            for (int i = 0; i < data.Count; ++i)
            {
                ASN1 entry = data[i];
                Add(new X509Certificate(entry[0].GetBytes()), new X509Crl(entry[1].GetBytes()));
            }
        }

        public void Add(X509Certificate cert, X509Crl crl)
        {
            certificates.Add(cert, crl);
        }

        public X509Certificate FindAuthorityCert(X509Chain chain)
        {
            X509CertificateCollection chainCerts = chain.Chain;
            for (int i = chainCerts.Count - 1; i >= 0; --i)
            {
                foreach(X509Certificate authorityCert in certificates.Keys)
                {
                    if (CryptoHelper.Compare(authorityCert.Hash, chainCerts[i].Hash))
                    {
                        return authorityCert;
                    }
                }
            }
            return null;
        }

        public bool IsRevoked(DateTime instant, X509Certificate cert, X509Certificate caCert)
        {
            X509Crl crl;
            if (certificates.TryGetValue(caCert, out crl))
            {
                X509Crl.X509CrlEntry entry = crl.GetCrlEntry(cert);
                if (entry != null)
                {
                    DateTime invalidityDate = DateTime.MinValue;

                    X509ExtensionCollection extensions = entry.Extensions;
                    X509Extension invalidityDateExtension = extensions["2.5.29.24"];
                    if (invalidityDateExtension != null)
                    {
                        invalidityDate = ASN1Convert.ToDateTime(invalidityDateExtension.Value[0]);
                    }

                    return instant > invalidityDate;
                }
            }
            return false;
        }

        public ASN1 GetData()
        {
            ASN1 data = new ASN1(0x30);
            foreach (var item in certificates)
            {
                ASN1 entry = new ASN1(0x30);
                entry.Add(new ASN1(item.Key.RawData));
                entry.Add(new ASN1(item.Value.RawData));
                data.Add(entry);
            }
            return data;
        }

        public IEnumerable<X509Certificate> Certificates
        {
            get
            {
                return certificates.Keys;
            }
        }
    }
}
