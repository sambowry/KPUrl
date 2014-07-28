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

#define TRACE

using System;
using System.Diagnostics;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Win32;

using KeePass.Plugins;
using KeePass.App;
using KeePass.App.Configuration;
using KeePass.UI;
using KeePass.Forms;
using KeePass.Util;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Utility;
using KeePassLib.Security;
using KeePassLib.Delegates;
using KeePassLib.Collections;

using RenameRegistryKey;

namespace KPUrl
{
	public sealed class KPUrlExt : Plugin
	{
		const string MyName = "KPUrl";

		private class TraceBox : Form
		{
			public static void Show(string str, string title = "")
			{
				Form box = new TraceBox();
				box.Text = MyName + " trace: " + title;
				TextBox t = new TextBox();
				t.Font = KeePass.UI.FontUtil.MonoFont;
				t.Text = str;
				t.Dock = DockStyle.Fill;
				t.Multiline = true;
				t.ScrollBars = ScrollBars.Both;
				t.WordWrap = false;
				t.ReadOnly = true;
				t.SelectionStart = 0;
				box.Controls.Add(t);
				box.ShowDialog();
			}
		}

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
			Trace.TraceInformation(MyName + " Initialize()");

			GlobalWindowManager.WindowAdded += WindowAddedHandler;
			IpcUtilEx.IpcEvent += OnIpcEvent;
			SprEngine.FilterCompilePre += OnFilterCompilePre;
			SprEngine.FilterCompile += OnFilterCompile;

			PwEntry.EntryTouched += OnTouched;

			RegisterAll();
			Application.ApplicationExit += new EventHandler(this.OnApplicationExit);
			System.Diagnostics.Process.GetCurrentProcess().Exited += new EventHandler(this.OnApplicationExit);
			return true;
		}

		private void OnTouched(object sender, ObjectTouchedEventArgs a)
		{
			if (a.Modified)
			{
				PwEntry pe = a.Object as PwEntry;
				if (pe != null) //&& e.str  a.strText.StartsWith("="))
				{
					PwDatabase pd = KeePass.Program.MainForm.DocumentManager.SafeFindContainerOf(pe);
					foreach (string fkey in pe.Strings.GetKeys())
					{
						string fval = pe.Strings.ReadSafe(fkey);
						if (fval.StartsWith("="))
						{
							Trace.TraceInformation("modified: " + pe.Strings.ReadSafe(PwDefs.TitleField));
							Trace.TraceInformation("    pre:'" + fkey + "' = '" + fval + "'");

							SprContext ctx = new SprContext(pe, pd, SprCompileFlags.All);
							string strText = SprEngine.Compile(fval.Substring(1), ctx);
							pe.Strings.Set(fkey, new ProtectedString(pe.Strings.Get(fkey).IsProtected, strText));
							pe.Touch(true);
							Trace.TraceInformation("   post:'" + fkey + "' = '" + strText + "'");
						}
					}
					//KeePass.Program.MainForm.Refresh();
				}
			}
		}

		private void OnIpcEvent(object sender, IpcEventArgs a)
		{
			if (m_debug && ShowIpcEventArgs(a) != DialogResult.OK) return;
			Trace.TraceInformation(MyName + " IpcEventArgs.name = '" + a.Name + "'");
			if (!String.Equals(a.Name, MyName, StringComparison.OrdinalIgnoreCase)) return;
			string url = a.Args.FileName;
			Trace.TraceInformation(MyName + " IpcEventArgs.Args.FileName = '" + url + "'");
			string scheme = url.Substring(0, url.IndexOf(":"));
			bool has_authority = url.StartsWith(scheme + "://");

			if (scheme.Equals("kp", StringComparison.OrdinalIgnoreCase))
			{
				scheme = "URL";
				url = scheme + url.Substring(url.IndexOf(":"));
			}
			Trace.TraceInformation(MyName + " scheme = '" + scheme + "'");
			Trace.TraceInformation(MyName + " url = '" + url + "'");

			string hostname = UrlUtil.GetHost(url);
			string userinfo = "";
			try
			{
				Uri uri = new Uri(url);
				userinfo = uri.UserInfo;
			}
			catch (Exception e) { MessageBox.Show("new Uri('" + url + "')\r\n" + e.Message, "OnIpcEvent()"); }

			PwEntry pe;
			string fn, fv = null;
			userinfo = GetAccountInfo(userinfo);
			Trace.TraceInformation(MyName + " userinfo = '" + userinfo + "'");
			if (has_authority || !FindHostEntry(scheme, hostname, out pe, out fn))
			{
				pe = new PwEntry(false, false);
				pe.Strings.Set(fn = PwDefs.UrlField, new KeePassLib.Security.ProtectedString(false, url));
				Trace.TraceInformation(MyName + " new PwEntry('" + url + "')");
			}
			fv = pe.Strings.ReadSafe(fn);
			if (!String.IsNullOrEmpty(url))
			{
				Trace.TraceInformation(MyName + " OpenUrl('" + fn + "' = '" + fv + "')");
				KeePass.Util.WinUtil.OpenUrl(fv, pe, true);
			}
			else
				MessageBox.Show("No suitable URL entry found for '" + a.Args.FileName + "'",
					MyName + ", OnEventMsgReceived()", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}

		private void WindowAddedHandler(object aSender, GwmWindowEventArgs aEventArgs)
		{
			Trace.TraceInformation("WindowAddedHandler(aEventArgs.Form.Name = '" + aEventArgs.Form.Name + "')");
			var optionsForm = aEventArgs.Form as OptionsForm;
			if (optionsForm != null)
			{
				optionsForm.FormClosed +=
					delegate(object sender, FormClosedEventArgs args)
					{
						if (optionsForm.DialogResult == DialogResult.OK)
						{
							DeRegisterAll();
							RegisterAll();
						}
					};
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
				MessageBoxButtons.OKCancel, MessageBoxIcon.None);
			return res;
		}

		private void OnApplicationExit(object sender, EventArgs e)
		{
			try
			{
				DeRegisterAll();
			}
			catch { }
		}

		public override void Terminate()
		{
			DeRegisterAll();
			GlobalWindowManager.WindowAdded -= WindowAddedHandler;
			IpcUtilEx.IpcEvent -= OnIpcEvent;
			SprEngine.FilterCompilePre -= OnFilterCompilePre;
			Trace.TraceInformation(MyName + " Terminate()");
		}

		private void RegisterProtocol(string protocol)
		{
			if (m_created.Contains(protocol)) return;
			//string exe = '"' + Application.ExecutablePath + '"';
			string exe = '"' + WinUtil.GetExecutable() + '"';
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
			try
			{
				RegistryKey key = classes.OpenSubKey(protocol, true);
				if (key != null)
				{
					string def = key.GetValue("", "").ToString();
					if (!def.StartsWith("URL:" + MyName, StringComparison.OrdinalIgnoreCase))
					{
						m_renamed.Add(protocol);
						if (classes.OpenSubKey(MyName + "-" + protocol) == null)
							ru.RenameSubKey(classes, protocol, MyName + "-" + protocol);
					}
				}

				m_created.Add(protocol);
				key = classes.CreateSubKey(protocol);
				key.SetValue("", "URL:" + MyName + " " + protocol + " protocol");
				key.SetValue("URL Protocol", "");
				key.SetValue("UseOriginalUrlEncoding", 1);

				key = key.CreateSubKey(@"shell");
				key.SetValue("", "open");

				key = key.CreateSubKey(@"open");
				key.SetValue("", "");

				key.CreateSubKey(@"command").SetValue("",
					exe + " -" + AppDefs.CommandLineOptions.IpcEvent + ":" + MyName + " \"%1\"");

				MyUriParser.Register(protocol);
			}
			catch (Exception e)
			{
				MessageBox.Show(e.Message, MyName + ", RegisterProtocol(" + protocol + ")",
					MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			classes.Close();
		}

		private void RegisterAll()
		{
			var o = KeePass.Program.Config.Integration.UrlSchemeOverrides;
			foreach (var l in new List<List<AceUrlSchemeOverride>> { /* o.BuiltInOverrides, */ o.CustomOverrides })
			{
				foreach (var u in l)
				{
					if (u.Enabled)
					{
						RegisterProtocol(u.Scheme);
					}
				}
			}
		}

		private void DeRegisterAll()
		{
			RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);

			foreach (string protocol in m_created)
			{
				try { classes.DeleteSubKeyTree(protocol); }
				catch (Exception e)
				{
					MessageBox.Show(e.Message, MyName + ", DeleteSubKeyTree(" + protocol + ")",
						MessageBoxButtons.OK, MessageBoxIcon.Error);
				}
			}
			m_created = new List<string>();

			foreach (string protocol in m_renamed)
			{
				try { ru.RenameSubKey(classes, MyName + "-" + protocol, protocol); }
				catch (Exception e)
				{
					MessageBox.Show(e.Message, MyName + ", RenameSubKey( " + MyName + "-" + protocol + ", " + protocol + ")",
						MessageBoxButtons.OK, MessageBoxIcon.Error);
				}

			}
			m_renamed = new List<string>();

			classes.Close();
		}

		private string MatchEntry(PwDatabase pd, PwEntry pe, string scheme, string matchTitle, out int distance)
		{
			string peTitleRaw = pe.Strings.ReadSafe(PwDefs.TitleField);
			string peTitleStr = SprEngine.Compile(peTitleRaw, new SprContext(pe, pd, SprCompileFlags.All, false, false));

			if (peTitleStr.IndexOf(matchTitle, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				Trace.TraceInformation(MyName + "   MatchEntry found title: '"+peTitleStr+"'" );
				distance = 0;
				if (!String.Equals(peTitleStr, matchTitle, StringComparison.OrdinalIgnoreCase))
				{
					distance++;
				}
				string fn = scheme;
				foreach( string key in pe.Strings.GetKeys() )
				{
					if( key.Equals(fn,StringComparison.OrdinalIgnoreCase) )
					{
						fn = key;
						break;
					}
				}
				Trace.TraceInformation(MyName + "   ReadSafe('" + fn + "') = '" + pe.Strings.ReadSafe(fn) + "'");
				if (pe.Strings.ReadSafe(fn) != "")
				{
					return fn;
				}
				if (pe.Strings.ReadSafe(PwDefs.UrlField + "-" + scheme) != "")
				{
					return PwDefs.UrlField + "-" + scheme;
				}
				string URL = pe.Strings.ReadSafe(PwDefs.UrlField);
				if (URL != "")
				{
					string peScheme = URL.Substring(0, URL.IndexOf(":"));
					if (!String.Equals(peScheme, scheme, StringComparison.OrdinalIgnoreCase))
					{
						distance++;
						if (peScheme.IndexOf(scheme, StringComparison.OrdinalIgnoreCase) < 0)
						{
							distance++;
						}
					}
					return PwDefs.UrlField;
				}
			}
			distance = int.MaxValue;
			return null;
		}

		private bool FindHostEntry(string scheme, string hostName, out PwEntry entryFound, out string fieldNameFound)
		{
			if (!String.IsNullOrEmpty(hostName))
			{
				PwDatabase lastPwDatabase = null;
				PwEntry lastPwEntry = null;
				string fieldName = null;
				int lastDistance = int.MaxValue;

				Trace.TraceInformation(MyName + "   FindHostEntry(scheme='"+scheme+"', hostName='"+hostName+"')");

				PwGroup pg = new PwGroup(true, true, "search for '" + scheme + ":" + hostName + "'", PwIcon.EMailSearch);
				pg.IsVirtual = true;

				EntryHandler eh = delegate(PwEntry pe)
				{
					int distance;
					string fn = MatchEntry(lastPwDatabase, pe, scheme, hostName, out distance);
					if (fn != null)
					{
						pg.AddEntry(pe, false);
						if (distance < lastDistance)
						{
							lastPwEntry = pe;
							fieldName = fn;
							lastDistance = distance;
						}
						return distance != 0;
					}
					distance = int.MaxValue;
					return true;
				};

				List<PwDocument> docs = m_host.MainWindow.DocumentManager.Documents;
				foreach (PwDocument d in docs)
				{
					lastPwDatabase = d.Database;
					d.Database.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh);
					if (lastPwEntry != null && fieldName != null && lastDistance == 0)
					{
						entryFound = lastPwEntry;
						fieldNameFound = fieldName;
						Trace.TraceInformation(MyName + "   entryFound = '" + entryFound.Strings.ReadSafe(PwDefs.TitleField) + "'");
						Trace.TraceInformation(MyName + "   fieldNameFound = '" + fieldName + "'");
						return true;
					}
				}

				uint uNumGroups;
				uint uNumEntries;
				pg.GetCounts(true, out uNumGroups, out uNumEntries);
				if (uNumEntries > 0)
				{
					if (uNumEntries == 1)
					{
						int distance;
						entryFound = pg.Entries.GetAt(0);
						fieldNameFound = MatchEntry(KeePass.Program.MainForm.DocumentManager.FindContainerOf(entryFound),
							entryFound, scheme, hostName, out distance);
						return true;
					}
					KeePass.Program.MainForm.UpdateUI(false, null, false, null, true, pg, false);
					KeePass.Program.MainForm.RefreshEntriesList();
					KeePass.Program.MainForm.EnsureVisibleForegroundWindow(true, true);
				}
			}
			entryFound = null;
			fieldNameFound = null;
			return false;
		}

		private string GetAccountInfo(string userinfo)
		{
			if (userinfo != "" && !userinfo.StartsWith(":"))
			{
				string username = userinfo;
				int colon = userinfo.IndexOf(':');
				if (0 <= colon)
				{
					username = userinfo.Substring(0, colon);
					string password = userinfo.Substring(colon + 1);
					if (password != "")
						return userinfo;
				}
				List<PwDocument> docs = m_host.MainWindow.DocumentManager.Documents;
				EntryHandler eh = delegate(PwEntry pe)
					{
						if (username != pe.Strings.ReadSafe(PwDefs.TitleField))
							return true;
						userinfo = pe.Strings.ReadSafe(PwDefs.UserNameField) + ':' +
								   pe.Strings.ReadSafe(PwDefs.PasswordField);
						return false;
					};
				foreach (PwDocument d in docs)
					if (!d.Database.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh)) break;
			}
			return userinfo;
		}

		private void OnFilterCompilePre(object sender, SprEventArgs a)
		{
			if ((a.Context.Flags & SprCompileFlags.ExtNonActive) != SprCompileFlags.None)
			{
				SprCompileFlags saved_flags = a.Context.Flags;
				a.Context.Flags &= ~(SprCompileFlags.ExtActive | SprCompileFlags.ExtNonActive);
				int countEmpty;
				a.Text = Compile(a.Text, a.Context, out countEmpty);
				a.Context.Flags = saved_flags;
			}
		}

		private void OnFilterCompile(object sender, SprEventArgs a)
		{
			//if ((a.Context.Flags & SprCompileFlags.ExtNonActive) != SprCompileFlags.None)
			{
				int start = -1;
				while (0 <= (start = a.Text.IndexOf("{PASSWORD:", start + 1, StringComparison.OrdinalIgnoreCase)))
				{
					int end = a.Text.IndexOf("}", start);
					string plh = a.Text.Substring(start, end - start + 1);
					string pw = !a.Context.ForcePlainTextPasswords ? // && KeePass.Program.Config.MainWindow.IsColumnHidden(AceColumnType.Password) ?
							PwDefs.HiddenPassword : a.Text.Substring(start + 10, (end - 1) - (start + 10) + 1);
					a.Text = a.Text.Remove(start, end - start + 1);
					a.Text = a.Text.Insert(start, pw);
				}

				// {BASE:ACCOUNT} {BASE:ACCOUNT:USERNAME} {BASE:ACCOUNT:PASSWORD}
				// {BASE:PATH:1}
				// {BASE:AUTHORITY:0}
				// {BASE:QUERY:field}  field1=value1&field2=value2&field3=value3...   [&;/]

			}
		}

		public string Compile(string strText, SprContext ctx, out int countEmpty)
		{
			countEmpty = 0;
			bool doReplace = false;
			string fieldName = null;
			bool isProtected = false;
			/*
			if (strText.StartsWith("=") && ctx != null && ctx.Entry != null)
			{
				foreach (string fn in ctx.Entry.Strings.GetKeys())
				{
					if (strText == ctx.Entry.Strings.ReadSafe(fn))
					{
						fieldName = fn;
						isProtected = ctx.Entry.Strings.Get(fn).IsProtected;
						break;
					}
				}
				doReplace = (fieldName != null);
				strText = strText.Substring(1);
			}
			*/
			const string begin = "<(";
			const string end = ")>";
			int top_left = -begin.Length;
			//			while (0 <= (top_left = strText.IndexOf(begin, top_left + begin.Length)))
			while (0 <= (top_left = strText.IndexOf(begin)))
			{
				int bottom_left, bottom_right;
				string plh, replaced;
				do
				{
					bottom_right = strText.IndexOf(end, top_left + begin.Length) + end.Length - 1;
					bottom_left = strText.LastIndexOf(begin, bottom_right - end.Length);
					plh = strText.Substring(bottom_left + begin.Length,
						(bottom_right - end.Length) - (bottom_left + begin.Length) + 1);
					replaced = Compile_plh(plh, ctx);
					if (String.IsNullOrEmpty(replaced)) countEmpty++;
					strText = strText.Substring(0, bottom_left) + replaced + strText.Substring(bottom_right + 1);
				} while (top_left != bottom_left);
			}
			if (doReplace)
			{
				strText = SprEngine.Compile(strText, ctx);
				ctx.Entry.Strings.Set(fieldName, new ProtectedString(isProtected, strText));
				ctx.Entry.Touch(true);
			}
			return strText;
		}

		public string Compile_plh(string strText, SprContext ctx)
		{
			int top_left = -1;
			//			while (0 <= (top_left = strText.IndexOf("{", top_left + 1)))
			while (0 <= (top_left = strText.IndexOf("{")))
			{
				int bottom_left, bottom_right;
				string plh, replaced;
				do
				{
					bottom_right = strText.IndexOf("}", top_left + 1);
					bottom_left = strText.LastIndexOf("{", bottom_right - 1);
					plh = strText.Substring(bottom_left, bottom_right - bottom_left + 1);
					replaced = SprEngine.Compile(plh, ctx);
					if (plh == replaced) replaced = "";
					strText = strText.Substring(0, bottom_left) + replaced + strText.Substring(bottom_right + 1);
				} while (top_left != bottom_left);
			}
			return strText;
		}

	}
}
