//
//  KPUrlExt.cs
//
//  Author(s):
//      sambowry <sambowry@gmail.com>
//
//  Copyright (C) 2014 sambowry
//
//  This program is free software; you can redistribute it and/or
//  modify it under the terms of the GNU General Public License
//  as published by the Free Software Foundation; either version 2
//  of the License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, see <http://www.gnu.org/licenses>
//

using System;
using System.Windows.Forms;
using System.Collections.Generic;
//using System.Text.RegularExpressions;
using Microsoft.Win32;

using KeePass.App;
using KeePass.App.Configuration;
using KeePass.UI;
using KeePass.Util;
using KeePass.Util.Spr;
using KeePass.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Utility;
using KeePassLib.Delegates;
using KeePassLib.Collections;

using RenameRegistryKey;

namespace KPUrl
{
	public sealed class KPUrlExt : Plugin
	{
		const string MyName = "KPUrl";

		private IPluginHost m_host = null;
		private bool m_debug = false;

		private RegistryUtilities ru = new RegistryUtilities();
		private List<string> m_renamed = new List<string>();
		private List<string> m_created = new List<string>();

		public override bool Initialize(IPluginHost host)
		{
			if (host == null) return false;
			m_host = host;
			m_debug = (m_host.CommandLineArgs[AppDefs.CommandLineOptions.Debug] != null);

			AppConfigEx config = KeePass.Program.Config;
			foreach (AceUrlSchemeOverride url in config.Integration.UrlSchemeOverrides.BuiltInOverrides)
			{
				if (url.Enabled) RegisterProtocol(url.Scheme);
			}
			foreach (AceUrlSchemeOverride url in config.Integration.UrlSchemeOverrides.CustomOverrides)
			{
				if (url.Enabled) RegisterProtocol(url.Scheme);
			}

			IpcUtilEx.IpcEvent += OnIpcEvent;
			return true;
		}

		private void OnIpcEvent(object sender, IpcEventArgs a)
		{
			if (m_debug && ShowIpcEventArgs(a) != DialogResult.OK) return;

			if ( String.Equals(a.Name, MyName, StringComparison.OrdinalIgnoreCase) )
			{
				string URL = a.Args.FileName;
				string scheme = URL.Substring(0, URL.IndexOf(":") );
				string hostname = UrlUtil.GetHost(URL);
	
				if (hostname != "")
				{
					PwEntry entry;
					string fieldName;
					if (FindHostEntry(scheme, hostname, out entry, out fieldName))
					{
						PwEntry tmp = entry.CloneDeep();
						tmp.Strings.Set(PwDefs.UrlField, entry.Strings.GetSafe(fieldName));
						KeePass.Util.WinUtil.OpenEntryUrl(tmp);
					}
					else
					{
						MessageBox.Show("No suitable URL entry found for '" + a.Args.FileName + "'",
							MyName + ", OnEventMsgReceived()", MessageBoxButtons.OK, MessageBoxIcon.Error);
					}
				}
			}
		}

		private DialogResult ShowIpcEventArgs(IpcEventArgs a)
		{
			string s = "";
			s += "a.Name: '" + a.Name + "'\r\n\r\n";
			s += "a.Args:\r\n";
			s += "FileName: '" + a.Args.FileName + "'\r\n";
			s += "FileNames:\r\n";
			int i = 1;
			foreach (string f in a.Args.FileNames)
			{
				s += "  [" + i++ + "]: '" + f + "'\r\n";
			}
			s += "Parameters:\r\n";
			foreach (KeyValuePair<string, string> p in a.Args.Parameters)
			{
				s += "  '" + p.Key + "' = '" + p.Value + "'\r\n";
			}
			s += "\r\nURL:\r\n";
			try
			{
				Uri uri = new Uri(a.Args.FileName);
				s += "  OriginalString: '" + uri.OriginalString + "'\r\n";
				s += "  Scheme:         '" + uri.Scheme + "'\r\n";
				s += "  Authority:      '" + uri.Authority + "'\r\n";
				s += "  UserInfo:       '" + uri.UserInfo + "'\r\n";
				s += "  HostNameType:   '" + uri.HostNameType + "'\r\n";
				s += "  Host:           '" + uri.Host + "'\r\n";
				s += "  DnsSafeHost:    '" + uri.DnsSafeHost + "'\r\n";
				s += "  Port:           '" + uri.Port + "'\r\n";
				s += "  Segments:       '" + String.Join(",", uri.Segments) + "'\r\n";
				s += "  Query:          '" + uri.Query + "'\r\n";
				s += "  Fragment:       '" + uri.Fragment + "'\r\n";
			}
			catch (Exception e)
			{
				s += e.Message + "\r\n";
			}
			DialogResult res = MessageBox.Show(s, MyName + ", ShowIpcEventArgs()",
				MessageBoxButtons.OKCancel , MessageBoxIcon.None);
			return res;
		}

		public override void Terminate()
		{
			DeRegisterAll();
		}

		private void RegisterProtocol(string protocol)
		{
			string exe = '"' + Application.ExecutablePath + '"';
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			try
			{
				if ( classes.OpenSubKey(protocol) != null )
				{
					m_renamed.Add(protocol);
					if ( classes.OpenSubKey("KPUrl-"+protocol) == null )
						ru.RenameSubKey(classes, protocol, "KPUrl-"+protocol);
				}

				m_created.Add(protocol);
				RegistryKey key = classes.CreateSubKey(protocol);
				key.SetValue("", "URL:" + protocol + " protocol");
				key.SetValue("URL Protocol", "");
				key.SetValue("UseOriginalUrlEncoding", 1);

				key = key.CreateSubKey(@"shell\open");
				key.SetValue("", "&Open");

				key.CreateSubKey(@"command").SetValue( "",
					exe + " -" + AppDefs.CommandLineOptions.IpcEvent + ":" + MyName + " \"%1\"" );
			}
			catch { }
			classes.Close();
		}

		private void DeRegisterAll()
		{
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			foreach (string protocol in m_created)
			{
				try { classes.DeleteSubKeyTree(protocol); }
				catch { }
			}
			foreach (string protocol in m_renamed)
			{
				try { ru.RenameSubKey(classes, MyName+"-"+protocol, protocol); }
				catch { }
			}
			classes.Close();
		}

		private string MatchEntry(PwDatabase pd, PwEntry pe, string scheme, string matchTitle, out int distance)
		{
			distance = 128;
			string peTitleRaw = pe.Strings.ReadSafeEx(PwDefs.TitleField);
			string peTitleStr = SprEngine.Compile(peTitleRaw, new SprContext(pe, pd, SprCompileFlags.All, false, false));

			if (String.Equals(peTitleStr, matchTitle, StringComparison.OrdinalIgnoreCase))
			{
				if (pe.Strings.ReadSafeEx(scheme) != "")
				{
					distance = 0;
					return scheme;
				}
				if (pe.Strings.ReadSafeEx(PwDefs.UrlField+"-"+scheme) != "")
				{
					distance = 0;
					return PwDefs.UrlField+"-"+scheme;
				}
				string URL = pe.Strings.ReadSafeEx(PwDefs.UrlField);
				if (URL != "")
				{
					distance = 2;
					string peScheme = URL.Substring(0, URL.IndexOf(":") );
					if ( String.Equals(peScheme, scheme, StringComparison.OrdinalIgnoreCase) )
					{
						distance = 1;
					}
					return PwDefs.UrlField;
				}
			}
			return null;
		}

		private bool FindHostEntry(string scheme, string hostName, out PwEntry entryFound, out string fieldNameFound)
		{
			entryFound = null;
			fieldNameFound = null;
			PwDatabase lastPwDatabase = null;
			PwEntry lastPwEntry = null;
			string fieldName = null;

			EntryHandler eh = delegate(PwEntry pe)
			{
				int distance;
				string fn = MatchEntry(lastPwDatabase, pe, scheme, hostName, out distance);
				if (fn != null)
				{
					lastPwEntry = pe;
					fieldName = fn;
				}
				return fn == null;
			};

			List<PwDocument> docs = m_host.MainWindow.DocumentManager.Documents;
			foreach (PwDocument d in docs)
			{
				lastPwDatabase = d.Database;
				d.Database.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh);
				if (lastPwEntry != null && fieldName != null)
				{
					entryFound = lastPwEntry;
					fieldNameFound = fieldName;
					return true;
				}
			}
			return false;
		}
	}
}
