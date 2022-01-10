//using FiddlerCoreTest;
using BetVote.analyze;
using BetVote.libs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BetVote.lib
{
    public static class Hook
    {
     /// <summary>
        /// 取字符串中间
        /// </summary>
        /// <param name="str"></param>
        /// <param name="leftstr"></param>
        /// <param name="rightstr"></param>
        /// <returns></returns>
        public static string StringSub(this string str, string leftstr, string rightstr)
        {
            int i = 0;
            int nsize = str.Length;//文本总长度
            if (leftstr != "")
            {
                i = str.IndexOf(leftstr, StringComparison.Ordinal);
                if (i == -1)
                {
                    return "";
                }
                i += leftstr.Length;//左字符非空
            }
            if (rightstr != "")
            {
                nsize = str.IndexOf(rightstr, i, StringComparison.Ordinal);//右字符非空
                if (nsize == -1)
                {
                    return "";//返回空
                }
            }
            string temp = str.Substring(i, nsize - i);
            return temp;
        }

        public static string[] getStringList(string data, string left, string rigth, string contain)
        {
            int i = 0;//现位置
            List<string> list = new List<string>();
            while (true)
            {
                var nsize = data.IndexOf(left, i);
                if (nsize == -1)
                {
                    break;
                }
                i = nsize + left.Length;
                var size = data.IndexOf(rigth, i);//结尾
                if (size == -1)
                {
                    break;
                }
                string result = data.Substring(i, size - i);
                if (result.Contains(contain))
                {
                    list.Add(result);
                }

                i = size + rigth.Length;
            }
            return list.ToArray();
        }

        public static string GetDomain(this string url, bool isScheme = true)
        {
            string result = string.Empty;
            try
            {
                Uri uri = new Uri(url);
                var port = uri.Port != 80 && uri.Port != 443 ? ":" + uri.Port : "";
                result = isScheme == true ? $"{uri.Scheme}://{uri.Host}{port}" : $"{uri.Host}{port}";

            }
            catch { }
            return result;
        }
        public static string GetStrMd5(this string ConvertString)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            string t2 = BitConverter.ToString(md5.ComputeHash(UTF8Encoding.Default.GetBytes(ConvertString)));
            t2 = t2.Replace("-", "");
            return t2;
        }
        
        public static int GetCreatetime()
        {
            DateTime d = new DateTime(1970, 1, 1, 8, 0, 0);
            return Convert.ToInt32((DateTime.Now - d).TotalSeconds);
        }
        public static string getUrlEncode(this string str)
        {
            return System.Web.HttpUtility.UrlEncode(str);
        }
        public static string getUrlDecode(this string str)
        {
            return System.Web.HttpUtility.UrlDecode(str);
        }
        public static void KillProc(string strProcName)
        {
            try
            {
                //精确进程名  用GetProcessesByName
                foreach (Process p in Process.GetProcessesByName(strProcName))
                {
                    p.Kill();
                }
            }
            catch { }
        }

        public static object TmdGetMain(string url, string body = null, string cookies = null, object hook = null, string script = null, int[] position = null, string hookUrl = null, string title = "",string ua = null)
        {
            if (hookUrl == null || hookUrl == "")
            {
                hookUrl = url;
            }
            if (position == null)
            {
                position = new int[] { 0, 0, 450, 500 };
            }
            var shttp = new SHttp();
            var lib = Streams.libScript;
            try
            {
                JObject jobject = JObject.Parse(lib);
                lib = jobject["result"].ToString();
            }
            catch
            {
                lib = "";
            }
            if (string.IsNullOrEmpty(body) && !string.IsNullOrEmpty(script))
            {
                hookUrl = hookUrl + (hookUrl.Contains("?") ? "&hook=1" : "?hook=1");
                string iframe = "<script>" + script + lib + "</script>";
                var html = string.Concat(new string[]
                {
                    "<iframe id='ifr1' style='border:0' width=100% height=100% onload='typeof(onloads)==\"undefined\"? console.log(12306) : onloads();' src=\"",url,"\"></iframe>",
                });
                body = "<html><head><meta charset=\"utf-8\" /></head>" + iframe + html + "</html>";
            }
            if (!string.IsNullOrEmpty(body) && body.Contains("{getScriptLib}"))
            {
                body = body.Replace("{getScriptLib}", lib);
            }
            var obj = new
            {
                domain = hookUrl,
                cookie = cookies,
                body = body,
                title = title,
                position = position,
                hook = hook,
                useragent = ua
            };
            return obj;
        }

        public static object TmdGetForm(string url, string body = "", string cookies = "", int[] position = null,string ua = null)
        {
            if (position == null)
            {
                position = new int[] { 0, 0, 450, 500 };
            }
            if (body == null || body == "")
            {
                url = url + (url.Contains("?") ? "&hook=1" : "?hook=1");
                string iframe = "";
                var html = string.Concat(new string[]
                {
                        "<style>html,body{margin:0;padding:0;}</style>",
                        "<iframe id='ifr1' style='border:0' width=100% height=100% onload='' src=\"",url,"\"></iframe>",

                });
                body = "<html><head><meta charset=\"utf-8\" /></head>" + html + iframe + "</html>";
            }
            var obj = new
            {
                domain = url,
                cookie = cookies,
                body = body,
                title = "",
                useragent = ua,
                position = position,
            };
            return obj;
        }

        public static object TmdGetHook(string url, string body, string execjs)
        {
            return new { url = url, body = body, execjs = execjs };
        }
        public static string TmdGetRefreshHtml(string url)
        {

            return "<head><meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1; url=" + url + "\"/></head>{TMDCOOKIES}";
        }


        public static string TmdGetClickAnchorLink(string url, string AnchorLink = null,string cookies=null)
        {
            var html = string.Concat(new string[]
            {
                    "<style>html,body{margin:0;padding:0;}</style><script>window.alert = function(){};</script>",
                    "<iframe id='ifr1' style='border:0' width=100% height=100% onload='typeof(onloads)==\"undefined\"? console.log(12306) : onloads();' src=\"",url,"\"></iframe>",
            });

            if (!string.IsNullOrEmpty(AnchorLink))
            {
                string iframe = "<script>function onloads(){var if1 = document.getElementById('ifr1');if1.contentWindow.alert = function(){}; ifdoc = if1.contentWindow.document;inTime=self.setInterval('loopClick()',2000); } function loopClick(){var eleDoc = ifdoc.querySelector(\"" + AnchorLink + "\"); if(eleDoc){window.clearInterval(inTime);eleDoc.click();}}</script>";
                html += iframe;
            }
            return "<html><head><meta http-equiv=\"as-Options\" content=\"SAMEORIGIN\"><meta charset=\"utf-8\" /></head>{TMDCOOKIES}<script>document.cookie = \""+ cookies + "\"</script>" + html + "</html>";
        }
        public static string TmdGetTableHistory(List<string> title, List<string> body, string script)
        {
            var html = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\">" + script;
            html += "</head><body>";
            html += "<div class='header-belt-main'>";
            html += "<ul class='nav-main'>";
            var htmlTitle = "";
            var i = 0;
            foreach (var item in title)
            {
                i++;
                var actoin = "action_" + i;
                htmlTitle += "<li class=''>";
                htmlTitle += "<span class='icon-betList' onclick='" + actoin + "();'>";
                htmlTitle += item;
                htmlTitle += "</span></li>";
            }
            html += htmlTitle + "</ul></div>";
            i = 0;
            var htmlScript = "<script>";
            foreach (var item in body)
            {
                i++;
                var actoin = "function action_" + i + "(){";
                htmlScript += actoin + "var data='" + Convert.ToBase64String(Encoding.UTF8.GetBytes(item)) + "';";
                htmlScript += "document.getElementById(\"showbody\").innerHTML=utf8to16(window.atob(data));";
                htmlScript += "}";
            }
            html += htmlScript + "</script>";
            return html + "<div id='showbody'></div></body></html>";
        }

        public static void TmdBrowser(object obj)
        {
            var guid = Guid.NewGuid().ToString("N");
            var work = $"{System.Environment.CurrentDirectory}\\TmdBrowser";
            if (!Directory.Exists($"{work}\\temp"))
            {
                //File.Create($"{work}\\temp");
                System.IO.Directory.CreateDirectory($"{work}\\temp");
            }
            var json = $"temp\\{guid}.json";
            File.WriteAllText(work + "\\" + json, JsonConvert.SerializeObject(obj));
            var process = Process.Start(new ProcessStartInfo()
            {
                FileName = "TmdBrowser.exe",
                WorkingDirectory = work,
                Arguments = json
            });
            Task.Factory.StartNew(() =>
            {
                process.WaitForExit();
                try
                {
                    File.Delete(work + "\\" + json);
                    File.Delete(work + "\\" + json + ".cookie");
                }
                catch { }
            });
        }

        public class TmdResult
        {
            public string cookie { get; set; } = "";
            public string result { get; set; } = Streams.timeout;
        }

        public static TaskCompletionSource<TmdResult> TmdBrowserAsync(object obj)
        {
            var s = new TaskCompletionSource<TmdResult>();
            var guid = Guid.NewGuid().ToString("N");
            var work = $"{System.Environment.CurrentDirectory}\\TmdBrowser";
            if (!Directory.Exists($"{work}\\temp"))
            {
                //File.Create($"{work}\\temp");
                System.IO.Directory.CreateDirectory($"{work}\\temp");
            }
            var json = $"temp\\{guid}.json";
            File.WriteAllText(work + "\\" + json, JsonConvert.SerializeObject(obj));
            var process = Process.Start(new ProcessStartInfo()
            {
                FileName = "TmdBrowser.exe",
                WorkingDirectory = work,
                Arguments = json
            });
            Task.Factory.StartNew(() =>
            {
                var result = new TmdResult();
                var filename = work + "\\" + json;


                while(!File.Exists(filename + ".cookie") && !File.Exists(filename + ".result"))
                {
                    Thread.Sleep(100);
                }

                if (File.Exists(filename + ".cookie"))
                {
                    result.cookie = File.ReadAllText(filename + ".cookie");
                    File.Delete(filename + ".cookie");
                }
                if (File.Exists(filename + ".result"))
                {
                    result.result = File.ReadAllText(filename + ".result");
                    File.Delete(filename + ".result");
                }
                if (File.Exists(filename))
                {
                    File.Delete(filename);
                }
                s.TrySetResult(result);
            });
            return s;
        }

        public static TaskCompletionSource<TmdResult> TmdBrowserNewAsync(object obj)
        {
            var s = new TaskCompletionSource<TmdResult>();
            var guid = Guid.NewGuid().ToString("N");
            var work = $"{System.Environment.CurrentDirectory}\\TmdBrowser";
            if (!Directory.Exists($"{work}\\temp"))
            {
                //File.Create($"{work}\\temp");
                System.IO.Directory.CreateDirectory($"{work}\\temp");
            }
            var json = $"temp\\{guid}.json";
            File.WriteAllText(work + "\\" + json, JsonConvert.SerializeObject(obj));
            var process = Process.Start(new ProcessStartInfo()
            {
                FileName = "TmdBrowserNew.exe",
                WorkingDirectory = work,
                Arguments = json
            });
            Task.Factory.StartNew(() =>
            {
                process.WaitForExit();
                var result = new TmdResult();
                var filename = work + "\\" + json;
                if (File.Exists(filename + ".cookie"))
                {
                    result.cookie = File.ReadAllText(filename + ".cookie");
                    File.Delete(filename + ".cookie");
                }
                if (File.Exists(filename + ".result"))
                {
                    result.result = File.ReadAllText(filename + ".result");
                    File.Delete(filename + ".result");
                }
                if (File.Exists(filename))
                {
                    File.Delete(filename);
                }
                s.TrySetResult(result);
            });
            return s;
        }

        public static Process TmdBrowserNbbAsync(object obj)
        {
            var s = new TaskCompletionSource<TmdResult>();
            var guid = Guid.NewGuid().ToString("N");
            var work = $"{System.Environment.CurrentDirectory}\\TmdBrowser";
            if (!Directory.Exists($"{work}\\temp"))
            {
                //File.Create($"{work}\\temp");
                System.IO.Directory.CreateDirectory($"{work}\\temp");
            }
            var json = $"temp\\{guid}.json";
            File.WriteAllText(work + "\\" + json, JsonConvert.SerializeObject(obj));
            var process = Process.Start(new ProcessStartInfo()
            {
                FileName = work + "\\TmdBrowserNew.exe",
                WorkingDirectory = work,
                Arguments = json
            });

            Task.Factory.StartNew(() =>
            {
                var dic = Directory.GetFiles($"{work}\\temp");
                foreach (var item in dic)
                {
                    Console.WriteLine(item);

                    FileInfo fileInfo = new FileInfo(item);
                    if (fileInfo.Name.Contains("hook.txt"))
                    {
                        continue;
                    }
                    if ((DateTime.Now - fileInfo.LastWriteTime).TotalMinutes > 3)
                    {
                        File.Delete(item);
                    }
                }
            });

            return process;
        }

    }
}
