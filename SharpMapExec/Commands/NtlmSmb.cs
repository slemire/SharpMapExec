using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using static SharpMapExec.Helpers.SecurityContext;

namespace SharpMapExec.Commands
{
    public class NtlmSmb : ICommand
    {
        public static string CommandName => "ntlmsmb";

        public void Execute(Dictionary<string, string> arguments)
        {
            string[] user;
            string domain = "";
            string path = "";
            string destination = "";
            string[] computernames;
            string[] hashes = null;
            string[] passwords = null;
            string module = "";
            string moduleargument = "";
            List<string> flags = new List<string>();

            if (arguments.ContainsKey("/m"))
            {
                module = arguments["/m"];
            }
            if (arguments.ContainsKey("/module"))
            {
                module = arguments["/module"];
            }
            if (arguments.ContainsKey("/a"))
            {
                moduleargument = arguments["/a"];
            }
            if (arguments.ContainsKey("/argument"))
            {
                moduleargument = arguments["/argument"];
            }


            //
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            else
            {
                domain = ".";
            }

            if (arguments.ContainsKey("/user"))
            {
                if (File.Exists(arguments["/user"]))
                {
                    user = File.ReadAllLines(arguments["/user"]);
                }
                else
                {
                    string[] parts = arguments["/user"].Split('\\');
                    if (parts.Length == 2)
                    {
                        domain = parts[0];
                        user = parts[1].Split(',');
                    }
                    else
                    {
                        user = arguments["/user"].Split(',');
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] /user must be supplied!");
                return;
            }

            if (arguments.ContainsKey("/computername"))
            {   
                // match cidr notation
                string cidr = @"/\d{1,3}$";
                Regex r = new Regex(cidr, RegexOptions.IgnoreCase);
                Match m = r.Match(arguments["/computername"]);
                if (m.Success)
                {
                    IPNetwork ipn = IPNetwork.Parse(arguments["/computername"]);
                    IPAddressCollection ips = IPNetwork.ListIPAddress(ipn);
                    List<string> iplist = new List<string>();
                    foreach (IPAddress ip in ips)
                    {
                        iplist.Add(ip.ToString());
                    }
                    computernames = iplist.ToArray();
                }
                else if (File.Exists(arguments["/computername"]))
                {
                    computernames = File.ReadAllLines(arguments["/computername"]);
                }
                else
                {
                    computernames = arguments["/computername"].Split(',');
                }
            }
            else
            {
                Console.WriteLine("[-] /computername must be supplied!");
                return;
            }

            if (arguments.ContainsKey("/password"))
            {
                if (File.Exists(arguments["/password"]))
                {
                    passwords = File.ReadAllLines(arguments["/password"]);
                }
                else
                {
                    passwords = arguments["/password"].Split(',');
                }
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                if (File.Exists(arguments["/ntlm"]))
                {
                    hashes = File.ReadAllLines(arguments["/ntlm"]);
                }
                else
                {
                    hashes = arguments["/ntlm"].Split(',');
                }
            }
            else
            {
                Console.WriteLine("[-] /password or /ntlm must be supplied");
                return;
            }
            Lib.ntlm.Ntlm(user, domain, passwords, hashes, computernames, "", module, moduleargument, path, destination, flags, "smb");
        }
    }
}