<%@ Page Language="C#" %>
<%@ Import Namespace= "System.Security.Cryptography" %>
<%@ Import Namespace= "System.Text" %>
<%@ Import Namespace= "System.IO" %>
<script runat="server" type="text/C#">
string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
{
    // Check arguments.
    if (cipherText == null || cipherText.Length <= 0)
        throw new ArgumentNullException("cipherText");
    if (Key == null || Key.Length <= 0)
        throw new ArgumentNullException("Key");
    if (IV == null || IV.Length <= 0)
        throw new ArgumentNullException("IV");

    // Declare the string used to hold
    // the decrypted text.
    string plaintext = null;

    // Create an AesManaged object
    // with the specified key and IV.
    using (AesManaged aesAlg = new AesManaged())
    {
        aesAlg.Key = Key;
        aesAlg.IV = IV;

        // Create a decrytor to perform the stream transform.
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        // Create the streams used for decryption.
        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        {
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {

                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = srDecrypt.ReadToEnd();
                }
            }
        }

    }
    return plaintext; 
}
</script>
<%
string encryptedUserProfile=Request.QueryString["encryptedUserProfile"];
string b;
byte[] hex=new byte[encryptedUserProfile.Length/2];
for(int i=0; i<hex.Length; i++) {
    b=encryptedUserProfile.Substring(0,2);
    Response.Write(b+";");
    hex[i]=Convert.ToByte(b,16);
    encryptedUserProfile=encryptedUserProfile.Substring(2);
}
var session_id=System.Web.HttpContext.Current.Session.SessionID;
HashAlgorithm hashAlgo = SHA256.Create();
byte[] conckey_bytes=hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(session_id));
string conckey = BitConverter.ToString(conckey_bytes).Replace("-","");
conckey = conckey.Substring(0,conckey.Length);

UTF8Encoding utf8 = new UTF8Encoding();
byte[] key = utf8.GetBytes(conckey).Take<byte>(256 / 8).ToArray<byte>();
byte[] IV = utf8.GetBytes(conckey).Take<byte>(128 / 8).ToArray<byte>();
Response.Write("<br>" + key[0].ToString() + key[31].ToString());
//string decrypted= DecryptStringFromBytes_Aes(hex, key, IV);
//Response.Write("<br>" + decrypted);
%>
