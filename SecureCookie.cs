using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections.Specialized;
using System.Text;
using System.Web.Security;

namespace Point4
{
    public abstract class SecureCookie
    {
        public HttpCookie Cookie { get; protected set; }
        public bool IsEncrypted { get; protected set; }

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

        public abstract EncryptedCookie Encrypt();
        public abstract DecryptedCookie Decrypt();        

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
            return new EncryptedCookie (cookie);
        }
    }

    public class EncryptedCookie : SecureCookie
    {
       
        public EncryptedCookie(HttpCookie cookie) : base(cookie)
        {
            cookie.Value = encrypt (cookie.Value);
            this.IsEncrypted = true;
        }

        public EncryptedCookie(DecryptedCookie cookie) : this(cookie.Cookie)
        {

        }

        private string encrypt(string message)
        {
            return MachineKey.Encode (Encoding.Unicode.GetBytes (message), MachineKeyProtection.Encryption);
        }

        public override EncryptedCookie Encrypt()
        {
            return this;
        }

        public override DecryptedCookie Decrypt()
        {
            return new DecryptedCookie (this);
        }
    }

    public class DecryptedCookie : SecureCookie
    {

        public DecryptedCookie(EncryptedCookie cookie) : this(cookie.Cookie)
        {
            
        }

        public DecryptedCookie(HttpCookie cookie) : base (cookie, true)
        {
            decrypt (cookie);
            this.Cookie = cookie;
            this.IsEncrypted = false;
        }
      
        public override EncryptedCookie Encrypt()
        {
            return new EncryptedCookie (this.Cookie);
        }

        public override DecryptedCookie Decrypt()
        {
            return this;
        }

        void decrypt(HttpCookie cookie)
        {
            try
            {
                var values = Encoding.Unicode.GetString (MachineKey.Decode (cookie.Value, MachineKeyProtection.Encryption)).Replace ("%3d", "=").Replace ("%26", ";").Split ('&');

                if (values.Length > 0)
                {
                    cookie.Values.Clear ();

                    if (values.All (x => x.Contains ("=") && !x.EndsWith ("=")))
                    {
                        foreach (var value in values)
                        {
                            var kv = value.Split ('=');

                            cookie.Values.Add (kv[0], kv[1]);
                        }
                    }
                    else
                    {
                        cookie.Value = values[0];
                    }
                }
            }
            catch (HttpException ex)
            {
                if (ex.Message == "Unable to validate data.")
                {
                    //assume cookie is not encrypted
                }
                else
                    throw;
            }

            IsEncrypted = false;                
        }
    }
}