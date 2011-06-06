using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Collections.Specialized;
using System.Web.Security;

namespace Harmony
{
    public class SecureCookie
    {
        public HttpCookie Cookie { get; private set; }
        public bool IsEncrypted { get; private set; }

        public string Name { get { return Cookie.Name; } set { Cookie.Name = value; } }
        public string Path { get { return Cookie.Path; } set { Cookie.Path = value; } }
        public bool Secure { get { return Cookie.Secure; } set { Cookie.Secure = value; } }
        public bool HttpOnly { get { return Cookie.HttpOnly; } set { Cookie.HttpOnly = value; } }
        public string Domain { get { return Cookie.Domain; } set { Cookie.Domain = value; } }
        public DateTime Expires { get { return Cookie.Expires; } set { Cookie.Expires = value; } }
        public string Value { get { return Cookie.Value; } }

        public bool? HasKeys
        {
            get
            {
                return IsEncrypted ? new Nullable<bool> () : new Nullable<bool> (Cookie.HasKeys);
            }
        }

        public NameValueCollection Values
        {
            get
            {
                return IsEncrypted ? new NameValueCollection () : Cookie.Values;
            }
        }

        public override string ToString()
        {
            return IsEncrypted ? "Encrypted Cookie" : Cookie.ToString ();
        }

        public void Encrypt()
        {
            if (!IsEncrypted)
            {
                this.Cookie.Value = MachineKey.Encode (Encoding.Unicode.GetBytes (this.Value), MachineKeyProtection.Encryption);
                IsEncrypted = true;
            }
        }

        public void Decrypt()
        {
            if (IsEncrypted)
            {
                IsEncrypted = false;
                var values = Encoding.Unicode.GetString (MachineKey.Decode (this.Value, MachineKeyProtection.Encryption)).Replace ("%3d", "=").Replace ("%26", ";").Split ('&');

                if (values.Length > 0 && values.All(x => x.Contains("=") && !x.EndsWith("=") ))
                {
                    this.Cookie.Values.Clear ();

                    foreach (var value in values)
                    {
                        var kv = value.Split ('=');

                        Cookie.Values.Add (kv[0], kv[1]);
                    }
                }


            }
        }

        public SecureCookie(HttpCookie cookie, bool isEncrypted = false)
        {
            this.Cookie = cookie;
            this.IsEncrypted = isEncrypted;
        }        

        public SecureCookie(string Name, string Value)
        {
            this.Cookie = new HttpCookie (Name, Value);
        }

        public SecureCookie(string Name, IDictionary<string, string> dictionary)
        {
            var cookie = new HttpCookie (Name);

            foreach (var kv in dictionary)
                cookie.Values.Add (kv.Key, kv.Value);

            this.Cookie = cookie;
        }

        public static implicit operator SecureCookie(HttpCookie cookie)
        {
            return new SecureCookie (cookie);
        }
    }
       

}
