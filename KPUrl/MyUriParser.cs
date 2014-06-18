
using System;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace KPUrl
{
	public sealed class MyUriParser : GenericUriParser
	{
		public MyUriParser(GenericUriParserOptions options) : base(options) { }

		public static void Register(string schemeName, int defaultPort = -1)
		{
			if (!UriParser.IsKnownScheme(schemeName))
				UriParser.Register(new MyUriParser(
					GenericUriParserOptions.Default |
					GenericUriParserOptions.DontCompressPath |
					GenericUriParserOptions.DontConvertPathBackslashes |
					GenericUriParserOptions.DontUnescapePathDotsAndSlashes |
					GenericUriParserOptions.GenericAuthority), schemeName, defaultPort);
		}

		private static Regex rx = new Regex(
				@"^(?<Scheme>[^:]+):"+
				@"(?://((?<User>[^@]+)@)?(?<Host>[^@:/?#]+)(:(?<Port>\d+))?)?" +
				@"(?<Path>([^?#]*)?)?(\?(?<Query>[^#]*))?(#(?<Fragment>.*))?$",
			RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.Singleline);
		private Match m = null;

		protected override void InitializeAndValidate(Uri uri, out UriFormatException parsingError)
		{
			m = rx.Match(uri.OriginalString);
			if (m.Success)
			{
				base.InitializeAndValidate(uri, out parsingError);
				parsingError = null;
			}
			else
			{
				MessageBox.Show("bad format: '" + uri.OriginalString + "'", "InitializeAndValidate()");
				parsingError = new UriFormatException("source: KPUrl.MyUriParser.InitializeAndValidate()");
			}
		}

		protected override string GetComponents(Uri uri, UriComponents components, UriFormat format)
		{
			string s;
			switch (components)
			{
				case UriComponents.Host:
					s = m.Groups["Host"].ToString();
					break;
				case UriComponents.Port:
					s = m.Groups["Port"].ToString();
					break;
				case UriComponents.StrongPort:
					s = m.Groups["Port"].Success ? m.Groups["Port"].ToString() : base.GetComponents(uri, UriComponents.StrongPort, format);
					break;
				case UriComponents.UserInfo:
					s = m.Groups["User"].ToString();
					break;
				case UriComponents.StrongAuthority:
					s = m.Groups["User"].Success ? m.Groups["User"].ToString() + "@" : "";
					s += m.Groups["Host"].ToString() + ":" + GetComponents(uri, UriComponents.StrongPort, format);
					break;
				default:
					s = base.GetComponents(uri, components, format);
					break;
			}
			return s;
		}

	}
}

/*

http://jmrware.com/articles/2009/uri_regexp/URI_regex.html

URI		scheme ":" hier-part [ "?" query ] [ "#" fragment ]

[A-Za-z][A-Za-z0-9+\-.]* :                                      # scheme ":"
(?:                                                             # hier-part
      //
  (?:                                                             # authority
    (?: (?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})* @)?     # [ userinfo "@" ]
    (?:                                                           # host
      \[                                                          # IP-literal
      (?:
        (?:                                                       # IPv6address
          (?:                                                    (?:[0-9A-Fa-f]{1,4}:){6}
          |                                                   :: (?:[0-9A-Fa-f]{1,4}:){5}
          | (?:                            [0-9A-Fa-f]{1,4})? :: (?:[0-9A-Fa-f]{1,4}:){4}
          | (?: (?:[0-9A-Fa-f]{1,4}:){0,1} [0-9A-Fa-f]{1,4})? :: (?:[0-9A-Fa-f]{1,4}:){3}
          | (?: (?:[0-9A-Fa-f]{1,4}:){0,2} [0-9A-Fa-f]{1,4})? :: (?:[0-9A-Fa-f]{1,4}:){2}
          | (?: (?:[0-9A-Fa-f]{1,4}:){0,3} [0-9A-Fa-f]{1,4})? ::    [0-9A-Fa-f]{1,4}:
          | (?: (?:[0-9A-Fa-f]{1,4}:){0,4} [0-9A-Fa-f]{1,4})? ::
          ) (?:
              [0-9A-Fa-f]{1,4} : [0-9A-Fa-f]{1,4}
            | (?: (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) \.){3}
                  (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
            )
        |   (?: (?:[0-9A-Fa-f]{1,4}:){0,5} [0-9A-Fa-f]{1,4})? ::    [0-9A-Fa-f]{1,4}
        |   (?: (?:[0-9A-Fa-f]{1,4}:){0,6} [0-9A-Fa-f]{1,4})? ::
        )
      | [Vv][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+           # / IPvFuture
      )
      \]
    | (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}           # / IPv4address
         (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
    | (?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*            # / reg-name
    )
    (?: : [0-9]* )?                                               # [ ":" port ]
  )
    (?:/ (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})* )*  #   path-abempty
| /                                                             # / path-absolute
  (?:    (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+
    (?:/ (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})* )*
  )?
|        (?:[A-Za-z0-9\-._~!$&'()*+,;=@] |%[0-9A-Fa-f]{2})+     # / path-noscheme
    (?:/ (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})* )*
|        (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+     # / path-rootless
    (?:/ (?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})* )*
|                                                               # / path-empty
)
(?:\? (?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})* )?   # [ "?" query ]
(?:\# (?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})* )?   # [ "#" fragment ]

*/
