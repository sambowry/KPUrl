using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;
using System.Collections.Generic;
using Microsoft.Win32;

using KeePass.App;
using KeePass.App.Configuration;
using KeePass.UI;
using KeePass.Util;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;

using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Collections;

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

		private void ShowEventArgs(CommandLineArgs args)
		{
			string s = "";
			s += "FileName: '" + args.FileName + "'\r\n";
			s += "FileNames:\r\n";
			int i = 1;
			foreach (string f in args.FileNames)
			{
				s += "  [" + i++ + "]: '" + f + "'\r\n";
			}
			s += "Parameters:\r\n";
			foreach (KeyValuePair<string, string> a in args.Parameters)
			{
				s += "  '" + a.Key + "' = '" + a.Value + "'\r\n";
			}
			Uri uri = new Uri(args.FileName);
			s += "\r\nURL:\r\n";
			s += "  OriginalString: '" + uri.OriginalString + "'\r\n";
			s += "  Scheme:         '" + uri.Scheme + "'\r\n";
			s += "  DnsSafeHost:    '" + uri.DnsSafeHost + "'\r\n";

			MessageBox.Show(s, "KPUrl, ShowEventArgs()", MessageBoxButtons.OK, MessageBoxIcon.Information );
		}

		private DialogResult ShowEntry(PwDatabase db, PwEntry pe)
		{
			PwEntryForm pForm = new PwEntryForm();
			pForm.InitEx(pe, PwEditMode.ViewReadOnlyEntry, db, m_host.MainWindow.ClientIcons, false, false);
			DialogResult result = pForm.ShowDialog();
			UIUtil.DestroyForm(pForm);
			return result;
		}

		private bool MatchEntry( PwEntry pe, Uri uri)
		{
			if (String.Equals(pe.Strings.ReadSafe("Title"), uri.DnsSafeHost, StringComparison.OrdinalIgnoreCase))
			{
				try
				{
					Uri peUri = new Uri(pe.Strings.ReadSafe("URL"));
					return String.Equals(peUri.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase);
				}
				catch { }
			}
			return false;
		}

		private PwEntry FindEntry(string url, bool show = false)
		{
			Uri uri = new Uri(url);
			var docs = m_host.MainWindow.DocumentManager.Documents;
			PwEntry found = null;
			foreach( PwDocument d in docs)
			{
				SearchParameters sp = new SearchParameters();
				PwObjectList<PwEntry> result = new PwObjectList<PwEntry>();
				d.Database.RootGroup.SearchEntries(sp, result);
				foreach(PwEntry entry in result)
				{
					if (MatchEntry(entry,uri))
					{
						if (show) ShowEntry(d.Database, entry);
						found = entry;
						break;
					}
				}
				if( found != null ) break;
			}
			return found;
		}

		private void OnEventMsgReceived(object sender, EventMsgArg e)
		{
			CommandLineArgs args = e.Args;
			if (String.Equals(args[AppDefs.CommandLineOptions.EventMsg], "KPUrl", StringComparison.OrdinalIgnoreCase))
			{
				ShowEventArgs(args);
				PwEntry entry = FindEntry(args.FileName, true);
				if (entry != null)
				{
					KeePass.Util.WinUtil.OpenEntryUrl(entry);
				}
				else
				{
					MessageBox.Show("No entry found for URL='" + args.FileName + "'",
						"KPUrl, OnEventMsgReceived()", MessageBoxButtons.OK, MessageBoxIcon.Error);
				}
			}
		}

		private bool IsRegistered( RegistryKey parentKey, string protocol)
		{
			RegistryKey key = parentKey.OpenSubKey(protocol);
			return (key != null);
		}

		private void RegisterProtocol(string protocol)
		{
			string exe = '"' + Application.ExecutablePath + '"';
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			try
			{
				if (IsRegistered(classes,protocol))
				{
					m_renamed.Add(protocol);
					if ( ! IsRegistered(classes,"KPUrl-" + protocol))
					{
						ru.RenameSubKey(classes, protocol, "KPUrl-" + protocol);
					}
				}

				m_created.Add(protocol);
				RegistryKey key = classes.CreateSubKey(protocol);
				key.SetValue("", "URL:" + protocol + " protocol");
				key.SetValue("URL Protocol", "");

				key = key.CreateSubKey(@"shell\open");
				key.SetValue("", "&Open");

				key.CreateSubKey(@"command").SetValue("", exe+" -event:KPUrl \"%1\"");
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
