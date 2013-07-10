using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Anomalous.Security
{
    class SigningException : Exception
    {
        public SigningException(String message)
            :base(message)
        {

        }
    }
}
