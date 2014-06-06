
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
@"^(?<Scheme>[^:]+)://((?<User>[^@]+)@)?(?<Host>[^@:/?#]+)(:(?<Port>\d+))?(/(?<Path>([^/][^?#]*)?))?(\?(?<Query>[^#]*))?(#(?<Fragment>.*))?$",
			RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.Singleline);
		private Match m;

		protected override void InitializeAndValidate(Uri uri, out UriFormatException parsingError)
		{
			m = rx.Match(uri.OriginalString);
			if (!m.Success)
				parsingError = new UriFormatException();
			else
				base.InitializeAndValidate(uri, out parsingError);
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
					/*
					string c = "";
					if (UriComponents.AbsoluteUri == (components & UriComponents.AbsoluteUri)) c += "AbsoluteUri\r\n";
					if (UriComponents.Fragment == (components & UriComponents.Fragment)) c += "Fragment\r\n";
					if (UriComponents.Host == (components & UriComponents.Host)) c += "Host\r\n";
					if (UriComponents.HostAndPort == (components & UriComponents.HostAndPort)) c += "HostAndPort\r\n";
					if (UriComponents.HttpRequestUrl == (components & UriComponents.HttpRequestUrl)) c += "HttpRequestUrl\r\n";
					if (UriComponents.KeepDelimiter == (components & UriComponents.KeepDelimiter)) c += "KeepDelimiter\r\n";
					if (UriComponents.Path == (components & UriComponents.Path)) c += "Path\r\n";
					if (UriComponents.PathAndQuery == (components & UriComponents.PathAndQuery)) c += "PathAndQuery\r\n";
					if (UriComponents.Port == (components & UriComponents.Port)) c += "Port\r\n";
					if (UriComponents.Query == (components & UriComponents.Query)) c += "Query\r\n";
					if (UriComponents.Scheme == (components & UriComponents.Scheme)) c += "Scheme\r\n";
					if (UriComponents.SchemeAndServer == (components & UriComponents.SchemeAndServer)) c += "SchemeAndServer\r\n";
					if (UriComponents.SerializationInfoString == (components & UriComponents.SerializationInfoString)) c += "SerializationInfoString\r\n";
					if (UriComponents.StrongAuthority == (components & UriComponents.StrongAuthority)) c += "StrongAuthority\r\n";
					if (UriComponents.StrongPort == (components & UriComponents.StrongPort)) c += "StrongPort\r\n";
					if (UriComponents.UserInfo == (components & UriComponents.UserInfo)) c += "UserInfo\r\n";
					MessageBox.Show(c + "\r\ns: " + s, "GetComponents()");
					*/
					break;
			}
			return s;
		}

	}
}