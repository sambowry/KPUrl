using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Win32;

using KeePass.App.Configuration;

using KeePass.Util;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;

using KeePassLib;
using KeePassLib.Security;

using RenameRegistryKey;

namespace KPUrl
{
	public sealed class KPUrlExt : Plugin
	{
		private IPluginHost m_host = null;

		private RegistryUtilities ru = new RegistryUtilities();
		private List<string> m_renamed = new List<string>();
		private List<string> m_created = new List<string>();

		public override bool Initialize(IPluginHost host)
		{
			if (host == null) return false;
			m_host = host;

			AppConfigEx config = KeePass.Program.Config;
			foreach (AceUrlSchemeOverride url in config.Integration.UrlSchemeOverrides.BuiltInOverrides)
			{
				if (url.Enabled) RegisterProtocol(url.Scheme);
			}
			foreach (AceUrlSchemeOverride url in config.Integration.UrlSchemeOverrides.CustomOverrides)
			{
				if (url.Enabled) RegisterProtocol(url.Scheme);
			}

			m_host.MainWindow.EventMsgReceived += OnEventMsgReceived;
			return true;
		}

		public override void Terminate()
		{
			DeRegisterAll();
		}

		private void OnEventMsgReceived(object sender, EventMsgArg e)
		{
			CommandLineArgs args = e.Args;
			string s = "";
			foreach(KeyValuePair<string,string> a in args.Parameters){
				s += "'" + a.Key + "' = '" + a.Value + "'\r\n";
			}
			MessageBox.Show("event args:\r\n" + s, "KPUrl", MessageBoxButtons.OK, MessageBoxIcon.Information);
		}

		private void RegisterProtocol(string protocol)
		{
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			string exe = '"' + Application.ExecutablePath + '"';
			try
			{
				RegistryKey subkey = classes.OpenSubKey(protocol,true);
				if (subkey != null)
				{
					subkey.Close();
					m_renamed.Add(protocol);
					ru.RenameSubKey(classes, protocol, "KPUrl-" + protocol);
				}

				m_created.Add(protocol);
				RegistryKey key = classes.CreateSubKey(protocol);
				key.SetValue("", "URL:" + protocol + " protocol");
				key.SetValue("URL Protocol", "");

				key = key.CreateSubKey(@"shell\open");
				key.SetValue("", "&Open");

				key.CreateSubKey(@"command").SetValue("", exe+" -event \"-KPUrl:%1\"");
			}
			catch(Exception e)
			{
				System.Windows.Forms.MessageBox.Show(e.Message, "KPUrl: RegisterProtocol('"+protocol+"')");
			}
			classes.Close();
		}

		private void DeRegisterAll()
		{
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			foreach (string protocol in m_created)
			{
				try
				{
					classes.DeleteSubKeyTree(protocol);
				}
				catch(Exception e)
				{
					System.Windows.Forms.MessageBox.Show(e.Message, "KPUrl: DeleteSubKey('" + protocol + "')");
				}
			}

			foreach (string protocol in m_renamed)
			{
				try
				{
					ru.RenameSubKey(classes, "KPUrl-" + protocol, protocol);
				}
				catch(Exception e)
				{
					System.Windows.Forms.MessageBox.Show(e.Message, "KPUrl: RenameSubKey('KPUrl-" + protocol + "', '" + protocol +"')");
				}
			}

			classes.Close();
		}

	}
}
