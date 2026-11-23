// notes-cli: a small command-line tool for the notes lab. INTENTIONALLY VULNERABLE.
// Veritas only reads the compiled assembly (dist/NotesCli.exe); it never runs it. Each planted weakness has an
// ID that expected-code-findings.yaml lists, next to a correct look-alike that must stay quiet.
// It targets C# 5, the language of the compiler that ships with Windows (tools/build.ps1).
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace NotesCli
{
    [Serializable]
    public class Note
    {
        public int Id;
        public string Title;
        public string Body;
    }

    public class Store
    {
        // D4: an access key in the code (a made-up value in the documented format).
        private const string ExportKey = "AKIAVRTFAKEKEY000001";
        private readonly string connection;

        public Store(string connection)
        {
            this.connection = connection;
        }

        // D1: the search term is joined into the SQL text.
        public int Search(string term)
        {
            using (var db = new SqlConnection(connection))
            using (var command = new SqlCommand("SELECT COUNT(*) FROM notes WHERE title LIKE '%" + term + "%'", db))
            {
                db.Open();
                return (int)command.ExecuteScalar();
            }
        }

        // Look-alike: the same search with the term bound as a parameter.
        public int SearchSafe(string term)
        {
            using (var db = new SqlConnection(connection))
            using (var command = new SqlCommand("SELECT COUNT(*) FROM notes WHERE title LIKE @term", db))
            {
                command.Parameters.AddWithValue("@term", "%" + term + "%");
                db.Open();
                return (int)command.ExecuteScalar();
            }
        }

        // D2: a binary formatter rebuilds whatever types the stream names.
        public Note Load(Stream stream)
        {
            return (Note)new BinaryFormatter().Deserialize(stream);
        }

        // Look-alike: a serializer bound to one type.
        public Note LoadSafe(Stream stream)
        {
            return (Note)new XmlSerializer(typeof(Note)).Deserialize(stream);
        }

        // D3: MD5 fingerprints.
        public string Fingerprint(byte[] data)
        {
            using (var md5 = MD5.Create())
            {
                return Convert.ToBase64String(md5.ComputeHash(data));
            }
        }

        // Look-alike: SHA-256.
        public string Checksum(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(data));
            }
        }

        // D5: the file name is joined into a command line that cmd.exe parses.
        public void Open(string file)
        {
            Process.Start("cmd.exe", "/c type " + file);
        }

        // Look-alike: the program and its argument stay separate, and no shell parses them.
        public void OpenSafe(string file)
        {
            Process.Start("notepad.exe", file);
        }

        // Uses the key, so the compiler writes it into the assembly as a string literal.
        public string Sign(string payload)
        {
            return payload + "." + ExportKey;
        }
    }

    public static class Program
    {
        public static int Main(string[] args)
        {
            Console.WriteLine("notes-cli is a Veritas lab subject. It does nothing when run.");
            return 0;
        }
    }
}
