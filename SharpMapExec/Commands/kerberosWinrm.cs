﻿using Rubeus;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

namespace SharpMapExec.Commands
{
    public class kerberosWinrm : ICommand
    {
        public static string CommandName => "kerberoswinrm";

        public void Execute(Dictionary<string, string> arguments)
        {
            string[] users = { };
            string domain = "";
            string path = "";
            string destination = "";
            string[] passwords = { };
            string[] hashes = { };
            string dc = "";
            string ticket = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;
            string[] computernames;
            string module = "";
            string moduleargument = "";
            List<string> flags = new List<string>();

            if (arguments.ContainsKey("/d"))
            {
                destination = arguments["/d"];
            }
            if (arguments.ContainsKey("/destination"))
            {
                destination = arguments["/destination"];
            }
            if (arguments.ContainsKey("/p"))
            {
                path = arguments["/p"];
            }
            if (arguments.ContainsKey("/path"))
            {
                path = arguments["/path"];
            }
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
            if (arguments.ContainsKey("/assystem") || arguments.ContainsKey("/system"))
            {
                flags.Add("system");
            }
            if (arguments.ContainsKey("/asdelegwalk") || arguments.ContainsKey("/delegwalk"))
            {
                flags.Add("delegwalk");
            }
            if (module.Contains("exec") && moduleargument.Length == 0)
            {
                Console.WriteLine("[-] Missing exec argument");
                return;
            }
            if (module.Contains("assembly") && !File.Exists(path))
            {
                Console.WriteLine("[-] Missing assembly path");
                return;
            }
            if (module.Contains("download") && (String.IsNullOrEmpty(path) || String.IsNullOrEmpty(destination)))
            {
                Console.WriteLine("[-] Need path and destination");
                return;
            }
            if (module.Contains("upload") && (String.IsNullOrEmpty(path) || String.IsNullOrEmpty(destination)))
            {
                Console.WriteLine("[-] Need path and destination");
                return;
            }


            //
            if (arguments.ContainsKey("/user"))
            {
                if (File.Exists(arguments["/user"]))
                {
                    users = File.ReadAllLines(arguments["/user"]);
                }
                else
                {
                    string[] parts = arguments["/user"].Split('\\');
                    if (parts.Length == 2)
                    {
                        domain = parts[0];
                        users = parts[1].Split(',');
                    }
                    else
                    {
                        users = arguments["/user"].Split(',');
                    }
                }
            }

            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/ticket"))
            {
                ticket = arguments["/ticket"];
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
                } else if (File.Exists(arguments["/computername"]))
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

            if (arguments.ContainsKey("/encType"))
            {
                string encTypeString = encType.ToString().ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM"))
                {
                    encType = Interop.KERB_ETYPE.rc4_hmac;
                }
                else if (encTypeString.Equals("AES128"))
                {
                    encType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES"))
                {
                    encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("DES"))
                {
                    encType = Interop.KERB_ETYPE.des_cbc_md5;
                }
            }
            else
                encType = Interop.KERB_ETYPE.rc4_hmac;

            if (arguments.ContainsKey("/password"))
            {
                if (File.Exists(arguments["/password"]))
                    passwords = File.ReadAllLines(arguments["/password"]);
                else
                    passwords = arguments["/password"].Split(',');
            }
            else if (arguments.ContainsKey("/des"))
            {
                if (File.Exists(arguments["/des"]))
                    hashes = File.ReadAllLines(arguments["/des"]);
                else
                    hashes = arguments["/des"].Split(',');
                encType = Interop.KERB_ETYPE.des_cbc_md5;
            }
            else if (arguments.ContainsKey("/rc4"))
            {
                if (File.Exists(arguments["/rc4"]))
                    hashes = File.ReadAllLines(arguments["/rc4"]);
                else
                    hashes = arguments["/rc4"].Split(',');
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                if (File.Exists(arguments["/ntlm"]))
                    hashes = File.ReadAllLines(arguments["/ntlm"]);
                else
                    hashes = arguments["/ntlm"].Split(',');
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.ContainsKey("/aes128"))
            {
                hashes = arguments["/aes128"].Split(',');
                encType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
            }
            else if (arguments.ContainsKey("/aes256"))
            {
                hashes = arguments["/aes256"].Split(',');
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }

            if (users.Length == 0 && String.IsNullOrEmpty(ticket))
            {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (String.IsNullOrEmpty(domain) && String.IsNullOrEmpty(ticket))
            {
                Console.WriteLine("\r\n[X] You must supply a domain!\r\n");
                return;
            }

            if ((hashes.Length == 0 && passwords.Length == 0) && String.IsNullOrEmpty(ticket))
            {
                Console.WriteLine("\r\n[X] You must supply a /password , or a [/des|/rc4|/aes128|/aes256] hash!\r\n");
                return;
            }

            if (String.IsNullOrEmpty(ticket) && (!((encType == Interop.KERB_ETYPE.des_cbc_md5) || (encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes128_cts_hmac_sha1) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1))))
            {
                Console.WriteLine("\r\n[X] Only /des, /rc4, /aes128, and /aes256 are supported at this time.\r\n");
                return;
            }

            Lib.kerberos.Kerberos(users, domain, passwords, hashes, ticket, encType, dc, computernames, module, moduleargument, path, destination, flags, "winrm");
        }
    }
}