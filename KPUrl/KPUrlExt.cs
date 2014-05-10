using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Win32;

using KeePass.App.Configuration;

using KeePass.Plugins;
using KeePass.Forms;
using KeePass.Resources;

using KeePassLib;
using KeePassLib.Security;

namespace KPUrl
{
  public sealed class KPUrlExt : Plugin
  {
    private IPluginHost m_host = null;

    public override bool Initialize(IPluginHost host)
    {
      if (host == null) return false;
      m_host = host;

      RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
      try
      {
        classes.DeleteSubKeyTree("KPUrl");
      }
      catch { }

      RegistryKey key = classes.CreateSubKey("KPUrl");
      key.SetValue("", "URL:KPUrl protocol");
      key.SetValue("URL Protocol", "");

      string exe = '"' + Application.ExecutablePath + '"';
      key.CreateSubKey("DefaultIcon").SetValue("", exe + ",1");
      key = key.CreateSubKey(@"shell\open");
      key.SetValue("", "&Open");

      key.CreateSubKey(@"command").SetValue("", exe + " \"-event:%1\"");

      m_host.MainWindow.EventMsgReceived += OnEventMsgReceived;

      return true;
    }

    private void OnEventMsgReceived(object sender, EventMsgArg e)
    {
      MessageBox.Show("event string: '" + e.Arg + "'", "KPUrl", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    public override void Terminate()
    {
      RegistryKey classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", true);
      try
      {
        classes.DeleteSubKeyTree("KPUrl");
      }
      catch { }
    }

  }
}
