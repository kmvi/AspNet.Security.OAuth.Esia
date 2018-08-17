using System;

namespace AspNet.Security.OAuth.Esia
{
    static class EsiaHelpers
    {
        public static string Base64UrlEncode(byte[] input)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (input.Length < 1)
                return String.Empty;

            string base64Str = null;
            int endPos = 0;
            char[] base64Chars = null;

            base64Str = Convert.ToBase64String(input);

            for (endPos = base64Str.Length; endPos > 0; endPos--)
            {
                if (base64Str[endPos - 1] != '=')
                {
                    break;
                }
            }

            base64Chars = new char[endPos + 1];
            base64Chars[endPos] = (char)((int)'0' + base64Str.Length - endPos);

            for (int iter = 0; iter < endPos; iter++)
            {
                char c = base64Str[iter];

                switch (c)
                {
                    case '+':
                        base64Chars[iter] = '-';
                        break;

                    case '/':
                        base64Chars[iter] = '_';
                        break;

                    case '=':
                        base64Chars[iter] = c;
                        break;

                    default:
                        base64Chars[iter] = c;
                        break;
                }
            }

            return new string(base64Chars);
        }

        public static byte[] Base64Decode(string input)
        {
            input = input.Replace('-', '+').Replace('_', '/');

            switch (input.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    input = String.Format("{0}==", input);
                    break;
                case 3:
                    input = String.Format("{0}=", input);
                    break;
                default:
                    throw new Exception("Illegal base64url string.");
            }

            return Convert.FromBase64String(input);
        }
    }
}
