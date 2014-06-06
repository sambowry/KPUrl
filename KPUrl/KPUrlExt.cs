﻿//
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
using System.Text.RegularExpressions;
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

			GlobalWindowManager.WindowAdded += WindowAddedHandler;
			IpcUtilEx.IpcEvent += OnIpcEvent;
			SprEngine.FilterCompilePre += OnFilterCompilePre;

			RegisterAll();
			return true;
		}

		private static Regex expr = new Regex(@"{([^{}]+)}", RegexOptions.Compiled | RegexOptions.Singleline);

		private void OnFilterCompilePre(object sender, SprEventArgs a)
		{
			if ((a.Context.Flags & SprCompileFlags.ExtNonActive) != SprCompileFlags.None)
			{
				SprCompileFlags saved_flags = a.Context.Flags;
				a.Context.Flags &= ~(SprCompileFlags.ExtActive | SprCompileFlags.ExtNonActive);
				string t1 = a.Text, t2;
				int count = 0;
				do
				{
					t1 = expr.Replace(t2 = t1,
						delegate(Match m)
						{
							string replaced = SprEngine.Compile(m.Value, a.Context);

							return replaced.Equals(m.Value) ? "" : replaced;
						});
				} while (++count < 20 && !t1.Equals(t2));
				a.Context.Flags = saved_flags;
				a.Text = t1;
			}
		}

		private void OnIpcEvent(object sender, IpcEventArgs a)
		{
			if (m_debug && ShowIpcEventArgs(a) != DialogResult.OK) return;
			if (!String.Equals(a.Name, MyName, StringComparison.OrdinalIgnoreCase)) return;
			string url = a.Args.FileName;
			string scheme = url.Substring(0, url.IndexOf(":"));
			string hostname = UrlUtil.GetHost(url);
			string userinfo = "";
			try
			{
				Uri uri = new Uri(url);
				userinfo = uri.UserInfo;
			}
			catch { }
			PwEntry pe;
			string fn, compiled = null;
			if (!String.IsNullOrEmpty(userinfo) || !FindHostEntry(scheme, hostname, out pe, out fn))
			{
				pe = new PwEntry(false, false);
				pe.Strings.Set(fn = PwDefs.UrlField, new KeePassLib.Security.ProtectedString(false, url));
			}
			GetOverrideForUrl(pe.Strings.ReadSafe(fn), pe, out compiled);
			if (!String.IsNullOrEmpty(compiled))
				KeePass.Util.WinUtil.OpenUrl(compiled, pe, false);
			else
				MessageBox.Show("No suitable URL entry found for '" + a.Args.FileName + "'",
					MyName + ", OnEventMsgReceived()", MessageBoxButtons.OK, MessageBoxIcon.Error);

		}

		string GetOverrideForUrl(string url, PwEntry pe, out string compiled)
		{
			string ovr = null, text = "";
			compiled = null;
			SprContext ctx = new SprContext(pe, KeePass.Program.MainForm.DocumentManager.FindContainerOf(pe),
										SprCompileFlags.All, false, false);
			ctx.ForcePlainTextPasswords = true;
			ctx.BaseIsEncoded = false; // ???
			ctx.Base = url;
			text += "Base: " + url + "\r\n";
			if (pe.OverrideUrl.Length > 0)
			{
				ovr = pe.OverrideUrl;
				compiled = SprEngine.Compile(ovr, ctx);
			}
			else if (KeePass.Program.Config.Integration.UrlOverride.Length > 0)
			{
				ovr = KeePass.Program.Config.Integration.UrlOverride;
				compiled = SprEngine.Compile(ovr, ctx);
			}
			else
			{
				Regex rx = new Regex("({(?>[^{}]+|(?'paren'{)|(?'-paren'}))*(?(paren)(?!))})");
				var o = KeePass.Program.Config.Integration.UrlSchemeOverrides;
				foreach (var l in new List<List<AceUrlSchemeOverride>> { o.BuiltInOverrides, o.CustomOverrides })
					foreach (var u in l)
						if (u.Enabled && url.StartsWith(u.Scheme + ":", StrUtil.CaseIgnoreCmp))
						{
							text += "AceUrlSchemeOverride: " + u.Scheme + ": " + u.UrlOverride + "\r\n";
							int countEmpty = 0;
							compiled = "";
							bool plh = false;
							string[] seg = rx.Split(u.UrlOverride);
							foreach (string s in seg)
							{
								text += "seg: " + s + "\r\n";
								string res1 = s, res2;
								do
								{
									res2 = res1;
									res1 = SprEngine.Compile(res2, ctx);
									text += "res: " + res1 + "\r\n";
								} while (!res1.Equals(res2));
								if (plh && res1.StartsWith("{"))
								{
									text += "empty: " + res1 + "\r\n";
									res1 = "";
								}
								if (plh && String.IsNullOrEmpty(res1) && !s.StartsWith("{C:", StringComparison.OrdinalIgnoreCase)) countEmpty++;
								compiled += res1;
								plh = !plh;
							}
							text += "compiled: " + compiled + "\r\n";
							text += "countEmpty: " + countEmpty + "\r\n";
							text += "\r\n";
							if (countEmpty == 0) goto ret;
						}
			}
		ret:
			if (m_debug) TraceBox.Show(text);
			return ovr;
		}

		private void WindowAddedHandler(object aSender, GwmWindowEventArgs aEventArgs)
		{
			var optionsForm = aEventArgs.Form as OptionsForm;
			if (optionsForm != null)
			{
				optionsForm.FormClosed += delegate(object sender, FormClosedEventArgs args)
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

		public override void Terminate()
		{
			DeRegisterAll();
			SprEngine.FilterCompilePre -= OnFilterCompilePre;
			GlobalWindowManager.WindowAdded -= WindowAddedHandler;
			IpcUtilEx.IpcEvent -= OnIpcEvent;
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
				distance = 0;
				if (!String.Equals(peTitleStr, matchTitle, StringComparison.OrdinalIgnoreCase))
				{
					distance++;
				}
				if (pe.Strings.ReadSafe(scheme) != "")
				{
					return scheme;
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
	}
}
