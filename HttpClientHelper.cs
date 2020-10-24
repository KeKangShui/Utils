using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using LookWater.Log;
using Polly;

namespace LookWater.Core
{
    public class HttpClientHelper
    {


        public static LookHttpClient Create(string url)
        {
            return LockHttpClientFactory.Create(url);
        }

        public static ConcurrentDictionary<string, Cookie> GetCookies(string url)
        {
            return LockHttpClientFactory.GetCookies(url);
        }

        /// <summary>
        ///     设置Cookie
        /// </summary>
        /// <param name="url"></param>
        /// <param name="item">Http参数</param>
        public static void SetCookie(string url, IDictionary<string, Cookie> item)
        {
            LockHttpClientFactory.SetCookie(url, item);
        }

        public static void SetCookie(string url, Cookie cookie)
        {
            LockHttpClientFactory.SetCookie(url, cookie);
        }
    }


    /// <summary>
    ///     Http请求参考类
    /// </summary>
    public class HttpItem : IDisposable
    {
        /// <summary>
        /// 是否检测返回状态码
        /// </summary>
        public bool IsCheckStatusCode { get; set; } = true;
        /// <summary>
        /// 是否检测返回值html 是否空
        /// </summary>
        public bool IsCheckResultHtml { get; set; } = true;

        /// <summary>
        /// 异常重试次数
        /// </summary>
        public int RetryTick { get; set; } = 3;
        /// <summary>
        /// 重试间隔(秒)
        /// </summary>
        public int RetryTimeSpan { get; set; } = 1;


        /// <summary>
        ///     请求URL必须填写
        /// </summary>
        public string URL { get; set; }

        /// <summary>
        ///     请求方式默认为GET方式,当为POST方式时必须设置Postdata的值
        /// </summary>
        public MethodEnum Method { get; set; } = MethodEnum.GET;


        /// <summary>
        ///     请求标头值 默认为
        ///     text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3,text/javascript,
        ///     application/javascript, application/ecmascript, application/x-ecmascript,application/json
        /// </summary>
        public string Accept { get; set; } =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3,text/javascript, application/javascript; q=0.01, application/ecmascript, application/x-ecmascript,application/json";

        /// <summary>
        ///     请求返回类型默认 text/html
        /// </summary>
        public string ContentType { get; set; } = "text/html";

        /// <summary>
        ///     客户端访问信息默认Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
        /// </summary>
        public string UserAgent { get; set; } = HtmlHelper.USERAGENT;

        /// <summary>
        ///     返回数据编码默认为NUll,可以自动识别,一般为utf-8,gbk,gb2312
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        ///     Post的数据类型
        /// </summary>
        public PostDataType PostDataType { get; set; } = PostDataType.String;

        /// <summary>
        ///     Post请求时要发送的字符串Post数据
        /// </summary>
        public string Postdata { get; set; }

        /// <summary>
        ///     Post请求时要发送的Byte类型的Post数据
        /// </summary>
        public byte[] PostdataByte { get; set; }

        ///// <summary>
        ///// Cookie对象集合
        ///// </summary>
        //public CookieCollection CookieCollection { get; set; } = new CookieCollection();

        /// <summary>
        ///     请求时的Cookie
        /// </summary>
        public string Cookie { get; set; }

        /// <summary>
        ///     来源地址，上次访问地址
        /// </summary>
        public string Referer { get; set; }


        /// <summary>
        ///     设置代理对象，不想使用IE默认配置就设置为Null，而且不要设置ProxyIp
        /// </summary>
        public WebProxy WebProxy { get; set; }


        /// <summary>
        ///     代理 服务IP,如果要使用IE代理就设置为ieproxy
        /// </summary>
        public string ProxyIp { get; set; }

        /// <summary>
        ///     设置返回类型String和Byte
        /// </summary>
        public ResultType ResultType { get; set; } = ResultType.String;

        /// <summary>
        ///     header对象
        /// </summary>
        public WebHeaderCollection Header { get; set; } = new WebHeaderCollection();

        /// <summary>
        ///     获取或设置用于请求的 HTTP 版本。返回结果:用于请求的 HTTP 版本。默认为 System.Net.HttpVersion.Version11。
        /// </summary>
        public Version ProtocolVersion { get; set; }


        /// <summary>
        ///     设置509证书集合
        /// </summary>
        public X509CertificateCollection ClentCertificates { get; set; }


        /// <summary>
        ///     Cookie返回类型,默认的是只返回字符串类型
        /// </summary>
        public ResultCookieType ResultCookieType { get; set; } = ResultCookieType.CookieCollection;

        public void Dispose()
        {
            URL = null;
            if (ClentCertificates != null)
            {
                ClentCertificates.Clear();
                ClentCertificates = null;
            }
            if (Header != null)
            {
                Header.Clear();
                Header = null;
            }
            ProxyIp = null;
            WebProxy = null;
            Referer = null;
            Cookie = null;
            PostdataByte = null;
            Postdata = null;
            UserAgent = null;
            ContentType = null;
            URL = null;
            UserAgent = null;
            ProtocolVersion = null;
            Encoding = null;
        }
    }

    public enum MethodEnum
    {
        POST,
        GET
    }

    /// <summary>
    ///     Http返回参数类
    /// </summary>
    public class HttpResult : IDisposable
    {
        public string Domain { get; set; }

        /// <summary>
        ///     Cookie对象集合
        /// </summary>
        public CookieCollection CookieCollection { get; set; } = new CookieCollection();

        /// <summary>
        ///     返回的String类型数据 只有ResultType.String时才返回数据，其它情况为空
        /// </summary>
        public string Html { get; set; } = string.Empty;

        /// <summary>
        ///     返回的Byte数组 只有ResultType.Byte时才返回数据，其它情况为空
        /// </summary>
        public byte[] ResultByte { get; set; }

        /// <summary>
        ///     header对象
        /// </summary>
        public HttpResponseHeaders Header { get; set; }

        /// <summary>
        ///     返回状态说明
        /// </summary>
        public string StatusDescription { get; set; }

        /// <summary>
        ///     返回状态码,默认为OK
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>
        ///     最后访问的URl
        /// </summary>
        public string ResponseUri { get; set; }

        /// <summary>
        ///     获取重定向的URl
        /// </summary>
        public string RedirectUrl { get; set; }

        public void Dispose()
        {
            Domain = null;
            CookieCollection = null;
            Html = null;
            ResultByte = null;
            StatusDescription = null;
            ResponseUri = null;
            RedirectUrl = null;
        }
    }

    /// <summary>
    ///     返回类型
    /// </summary>
    public enum ResultType
    {
        /// <summary>
        ///     表示只返回字符串 只有Html有数据
        /// </summary>
        String,

        /// <summary>
        ///     表示返回字符串和字节流 ResultByte和Html都有数据返回
        /// </summary>
        Byte
    }

    /// <summary>
    ///     Post的数据格式默认为string
    /// </summary>
    public enum PostDataType
    {
        /// <summary>
        ///     字符串类型，这时编码Encoding可不设置
        /// </summary>
        String,

        /// <summary>
        ///     Byte类型，需要设置PostdataByte参数的值编码Encoding可设置为空
        /// </summary>
        Byte,

        /// <summary>
        ///     传文件，Postdata必须设置为文件的绝对路径，必须设置Encoding的值
        /// </summary>
        FilePath,

        MultipartFormDataContent
    }

    /// <summary>
    ///     Cookie返回类型
    /// </summary>
    public enum ResultCookieType
    {
        /// <summary>
        ///     只返回字符串类型的Cookie
        /// </summary>
        String,

        /// <summary>
        ///     CookieCollection格式的Cookie集合同时也返回String类型的cookie
        /// </summary>
        CookieCollection
    }


    public class LockHttpClientFactory
    {
        private static readonly ConcurrentDictionary<string, LookHttpClient> clients = new ConcurrentDictionary<string, LookHttpClient>();

        public static LookHttpClient Create(string url)
        {
            var uri = new Uri(url);

            string[] domains = uri.Host.Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries);

            string newUrl = $"{domains[domains.Length - 2]}.{domains[domains.Length - 1]}";

            if (!clients.TryGetValue(newUrl, out var client))
            {
                client = CreateHttpClient(CreateMessageHandler(), url);
                clients.AddOrUpdate(newUrl, client, (k, v) => client);
            }
            return client;
        }

        protected static LookHttpClient CreateHttpClient(HttpMessageHandler handler, string url)
        {
            LookHttpClient lookHttp = new LookHttpClient(handler);
            lookHttp.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
            lookHttp.DefaultRequestHeaders.Add("Accept-Language", "zh-CN,zh;q=0.9");
            lookHttp.DefaultRequestHeaders.Connection.Add("keep-alive");
            lookHttp.Timeout = new TimeSpan(0, 0, 30);

            return lookHttp;
        }

        protected static HttpMessageHandler CreateMessageHandler()
        {
            var handler = new HttpClientHandler();
            handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            handler.UseCookies = false;
            handler.AllowAutoRedirect = false;
            handler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
            handler.MaxConnectionsPerServer = 256;

            return handler;
        }

        public static ConcurrentDictionary<string, Cookie> GetCookies(string url)
        {
            return (Create(url))?.GetCookies();
        }

        public static void SetCookie(string url, IDictionary<string, Cookie> _cookieContainer)
        {
            (Create(url))?.SetCookie(_cookieContainer);
        }


        public static void SetCookie(string host, Cookie item)
        {
            (Create(host))?.SetCookie(item);
        }
    }


    public class LookHttpClient : HttpClient
    {
        private readonly ConcurrentDictionary<string, Cookie> m_Cookies;

        public LookHttpClient(HttpMessageHandler handler) : base(handler)
        {
            m_Cookies = new ConcurrentDictionary<string, Cookie>();
        }

        /// <summary>
        ///     根据相传入的数据，得到相应页面数据
        /// </summary>
        /// <param name="item">参数类对象</param>
        /// <returns>返回HttpResult类型</returns>
        public async Task<HttpResult> GetHtmlAsync(HttpItem item)
        {
            //返回参数
            var result = new HttpResult();
            using var httpRequest = new HttpRequestMessage();

            try
            {
                //准备参数
                SetRequest(item, httpRequest);
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogDefine.LogError, ex, $"GetHtmlAsync,{ex.Message}");
                //配置参数时出错
                return new HttpResult
                { Header = null, Html = ex.Message, StatusDescription = "配置参数时出错：" + ex.StackTrace };
            }

            try
            {
                var resultResponse = await SendAsync(httpRequest);
                await GetData(item, resultResponse, result);
            }
            catch (HttpRequestException ex)
            {
                //LogHelper.Log(LogDefine.LogError, ex, $"GetResponseURL,{item.URL}");
                result.Html = ex.Message;
            }
            catch (Exception ex)
            {
                result.Html = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 根据相传入的数据，得到相应页面数据
        /// </summary>
        /// <param name="item">参数类对象</param>
        /// <returns>返回HttpResult类型</returns>
        public async Task<HttpResult> GetHtmlPolicyAsync(HttpItem item)
        {
            var retryPolicy = Policy.Handle<Exception>()
                //.OrResult<HttpResult>(new HttpResult() { Header = null, Html = null, StatusCode= HttpStatusCode.ExpectationFailed })
                .WaitAndRetryAsync(item.RetryTick, retryAttempt => TimeSpan.FromSeconds(item.RetryTimeSpan), (ex, time,count, context) =>
            {
                var http = (HttpItem)context["HttpItem"];
                LogHelper.Log(LogDefine.LogError, ex, $"http异常,url={http.URL},type={http.Method},第{count}次重试");
            });

            Context keys = new Context();
            keys.Add("HttpItem", item);

            var resultHtml = await retryPolicy.ExecuteAsync(async (content) => {
                HttpResult result = new HttpResult();
                using HttpRequestMessage httpRequest = new HttpRequestMessage();
                var http = (HttpItem)content["HttpItem"];
                try
                {
                    //准备参数
                    SetRequest(http, httpRequest);
                }
                catch (Exception ex)
                {
                    LogHelper.Log(LogDefine.LogError, ex, $"GetHtmlAsync,{ex.Message}");
                    //配置参数时出错
                    return new HttpResult() { Header = null, Html = ex.Message, StatusDescription = "配置参数时出错：" + ex.StackTrace };
                }
                var resultResponse = await SendAsync(httpRequest);


                if (http.IsCheckStatusCode && !resultResponse.IsSuccessStatusCode)
                {
                    throw new Exception($"http异常状态码，code={resultResponse.StatusCode},url={http.URL},type={http.Method},{result.Html}");
                }
                await GetData(http, resultResponse, result);

                if (http.IsCheckResultHtml && string.IsNullOrEmpty(result.Html))
                {
                    throw new Exception($"http异常,url={http.URL},type={http.Method},无任何返回值");
                }
                return result;
            }, keys);
            keys.Clear();
            return resultHtml;
        }




        /// <summary>
        ///     获取数据的并解析的方法
        /// </summary>
        /// <param name="item"></param>
        /// <param name="response"></param>
        /// <param name="result"></param>
        private async Task<HttpResult> GetData(HttpItem item, HttpResponseMessage response, HttpResult result)
        {
            if (response == null) return result;

            result.StatusCode = response.StatusCode;

            //获取Headers
            result.Header = response.Headers;
            result.ResponseUri = response.RequestMessage.RequestUri?.ToString();
            result.RedirectUrl = response.Headers.Location?.ToString();

            var domain = result.ResponseUri;
            if (!string.IsNullOrEmpty(result.RedirectUrl))
            {
                if (result.RedirectUrl.IndexOf("http", StringComparison.Ordinal) <= -1)
                {
                    Uri temp = new Uri(item.URL);
                    var tempProt = "";
                    if (temp.Port != 80 && temp.Port != 443) tempProt = $":{temp.Port}";
                    domain = $"{temp.Scheme}://{temp.Host}{tempProt}{result.RedirectUrl}";
                }
            }

            var url = new Uri(domain ?? item.URL);
            var prot = "";
            if (url.Port != 80 && url.Port != 443) prot = $":{url.Port}";
            result.Domain = $"{url.Scheme}://{url.Host}{prot}";

            var host = new Uri(result.Domain);

            if (!string.IsNullOrEmpty(result.RedirectUrl) && result.RedirectUrl.IndexOf("http", StringComparison.OrdinalIgnoreCase) <= -1)
                result.RedirectUrl = result.Domain + result.RedirectUrl;
            //获取set-cookie
            if (response.Headers.Contains("set-cookie"))
                if (response.Headers.TryGetValues("set-cookie", out var cookies))
                    foreach (var nowItem in cookies)
                    {
                        var nowCookies = CookieHelper.GetCookiesByHeader(nowItem, host);
                        foreach (var itemCookie in nowCookies)
                            m_Cookies.AddOrUpdate(itemCookie.Name, itemCookie, (k, v) => itemCookie);
                    }



            foreach (var cookie in m_Cookies) result.CookieCollection.Add(cookie.Value);
            //处理网页Byte
            var ResponseByte = await GetByte(item, response);
            if(item.ResultType == ResultType.Byte)
            {
                result.ResultByte = ResponseByte;
            }else if (ResponseByte != null && ResponseByte.Length > 0)
                result.Html = Encoding.UTF8.GetString(ResponseByte);
            else
                //没有返回任何Html代码
                result.Html = string.Empty;
            return result;
        }

        /// <summary>
        ///     提取网页Byte
        /// </summary>
        /// <returns></returns>
        private async Task<byte[]> GetByte(HttpItem HttpDataItem, HttpResponseMessage response)
        {
            byte[] ResponseByte = null;

            try
            {
                ResponseByte = await response.Content.ReadAsByteArrayAsync();
            }
            catch (WebException ex)
            {
                LogHelper.Log(LogDefine.LogError, ex, $"获取http返回流异常,{HttpDataItem.URL}");
                var exResponse = (HttpWebResponse)ex.Response;
                if (exResponse == null) return null;
                MemoryStream _stream = null;
                try
                {
                    using var stream = exResponse.GetResponseStream();
                    if (stream != null)
                    {
                        _stream = new MemoryStream();
                        if (exResponse.ContentEncoding.Equals("gzip", StringComparison.OrdinalIgnoreCase))
                        {
                            using var item = new GZipStream(stream, CompressionMode.Decompress);
                            await item.CopyToAsync(_stream, 10240);
                        }
                        else
                            await stream.CopyToAsync(_stream, 10240);

                        ResponseByte = _stream.ToArray();
                    }
                }
                catch
                {
                    _stream?.Dispose();
                }
            }

            return ResponseByte;
        }

        /// <summary>
        ///     为请求准备参数
        /// </summary>
        /// <param name="item">参数列表</param>
        /// <param name="httpRequest"></param>
        private void SetRequest(HttpItem item, HttpRequestMessage httpRequest)
        {
            //设置Header参数
            if (item.Header != null && item.Header.Count > 0)
                foreach (var key in item.Header.AllKeys)
                    if (!httpRequest.Headers.Contains(key))
                        httpRequest.Headers.Add(key, item.Header[key]);

            item.Header?.Clear();
            if (item.ProtocolVersion != null) httpRequest.Version = item.ProtocolVersion;
            httpRequest.RequestUri = new Uri(item.URL);
            httpRequest.Method = item.Method == MethodEnum.GET ? HttpMethod.Get : HttpMethod.Post;

            if (!httpRequest.Headers.Contains("Referer") && !string.IsNullOrEmpty(item.Referer))
                httpRequest.Headers.Add("Referer", item.Referer);

            if (!httpRequest.Headers.Contains("Accept") && !string.IsNullOrEmpty(item.Accept))
                httpRequest.Headers.Add("Accept", item.Accept);
            if (!httpRequest.Headers.Contains("User-Agent") && !string.IsNullOrEmpty(item.UserAgent))
                httpRequest.Headers.Add("User-Agent", item.UserAgent);

            SetCookie(httpRequest);

            SetPostData(item, httpRequest);
        }


        /// <summary>
        ///     设置Post数据
        /// </summary>
        /// <param name="item">Http参数</param>
        /// <param name="httpRequest"></param>
        private void SetPostData(HttpItem item, HttpRequestMessage httpRequest)
        {
            //验证在得到结果时是否有传入数据
            if (httpRequest.Method != HttpMethod.Get)
            {
                HttpContent content = null;
                //写入Byte类型
                if (item.PostDataType == PostDataType.Byte && item.PostdataByte != null && item.PostdataByte.Length > 0)
                    content = new ByteArrayContent(item.PostdataByte);
                else if (item.PostDataType == PostDataType.String && !string.IsNullOrWhiteSpace(item.Postdata))
                    content = new StringContent(item.Postdata);
                if (content != null)
                {
                    content.Headers.ContentType = new MediaTypeHeaderValue(item.ContentType);
                    httpRequest.Content = content;
                }
            }
        }

        private void SetCookie(HttpRequestMessage httpRequest)
        {
            var sb = new StringBuilder();
            foreach (var item in m_Cookies)
            {
                if(!string.IsNullOrEmpty(item.Key))
                {
                    sb.Append($"{item.Key}={item.Value.Value};");
                }
            }

            httpRequest.Headers.Add("Cookie", sb.ToString());
        }

        public ConcurrentDictionary<string, Cookie> GetCookies()
        {
            return m_Cookies;
        }


        /// <summary>
        ///     设置Cookie
        /// </summary>
        /// <param name="items">Http参数</param>
        public void SetCookie(IDictionary<string, Cookie> items)
        {
            foreach (var item in items) m_Cookies.AddOrUpdate(item.Key, item.Value, (k, v) => item.Value);
        }

        public void SetCookie(Cookie item)
        {
            m_Cookies.AddOrUpdate(item.Name, item, (k, v) => item);
        }


        #region IDisposable Support

        private bool disposedValue; // 要检测冗余调用

        protected override void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 释放托管状态(托管对象)。
                }

                m_Cookies.Clear();
                //cookieContainer = null;
                disposedValue = true;
            }
        }

        #endregion
    }

    /// <summary>
    ///     Cookie 助手
    /// </summary>
    public class CookieHelper
    {
        /// <summary>
        ///     解析Cookie
        /// </summary>
        private static readonly Regex RegexSplitCookie2 = new Regex(@"[^,][\S\s]+?;+[\S\s]+?(?=,\S)");

        /// <summary>
        ///     获取所有Cookie 通过Set-Cookie
        /// </summary>
        /// <param name="setCookie"></param>
        /// <param name="host"></param>
        /// <returns></returns>
        public static List<Cookie> GetCookiesByHeader(string setCookie, Uri host)
        {
            var cookieCollection = new List<Cookie>();
            //拆分Cookie
            //var listStr = RegexSplitCookie.Split(setCookie);
            setCookie += ",T"; //配合RegexSplitCookie2 加入后缀
            var listStr = RegexSplitCookie2.Matches(setCookie);
            //循环遍历
            foreach (Match item in listStr)
            {
                //根据; 拆分Cookie 内容
                var cookieItem = item.Value.Split(';');
                var cookie = new Cookie();
                for (var index = 0; index < cookieItem.Length; index++)
                {
                    var info = cookieItem[index];
                    //第一个 默认 Cookie Name
                    //判断键值对
                    if (info.Contains("="))
                    {
                        var indexK = info.IndexOf('=');
                        var name = info.Substring(0, indexK).Trim();
                        var val = info.Substring(indexK + 1);
                        if (index == 0)
                        {
                            cookie.Name = name;
                            cookie.Value = val;
                            continue;
                        }

                        if (name.Equals("Domain", StringComparison.OrdinalIgnoreCase))
                        {
                            cookie.Domain = val;
                        }
                        else if (name.Equals("Expires", StringComparison.OrdinalIgnoreCase))
                        {
                            DateTime.TryParse(val, out var expires);
                            cookie.Expires = expires;
                        }
                        else if (name.Equals("Path", StringComparison.OrdinalIgnoreCase))
                        {
                            cookie.Path = val;
                        }
                        else if (name.Equals("Version", StringComparison.OrdinalIgnoreCase))
                        {
                            cookie.Version = Convert.ToInt32(val);
                        }
                    }
                    else
                    {
                        if (info.Trim().Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)) cookie.HttpOnly = true;
                    }
                }

                if (host != null) cookie.Domain = host.Host;
                cookieCollection.Add(cookie);
            }

            return cookieCollection;
        }

        /// <summary>
        ///     获取 Cookies
        /// </summary>
        /// <param name="setCookie"></param>
        /// <param name="uri"></param>
        /// <returns></returns>
        public static string GetCookies(string setCookie, Uri uri)
        {
            //获取所有Cookie
            var strCookies = string.Empty;
            var cookies = GetCookiesByHeader(setCookie, uri);
            foreach (var cookie in cookies)
            {
                //忽略过期Cookie
                if (cookie.Expires < DateTime.Now && cookie.Expires != DateTime.MinValue) continue;
                if (uri.Host.Contains(cookie.Domain)) strCookies += $"{cookie.Name}={cookie.Value}; ";
            }

            return strCookies;
        }

        /// <summary>
        ///     通过Name 获取 Cookie Value
        /// </summary>
        /// <param name="setCookie">Cookies</param>
        /// <param name="name">Name</param>
        /// <returns></returns>
        public static string GetCookieValueByName(string setCookie, string name)
        {
            var regex = new Regex($"(?<={name}=).*?(?=; )");
            return regex.IsMatch(setCookie) ? regex.Match(setCookie).Value : string.Empty;
        }

        /// <summary>
        ///     通过Name 设置 Cookie Value
        /// </summary>
        /// <param name="setCookie">Cookies</param>
        /// <param name="name">Name</param>
        /// <param name="value">Value</param>
        /// <returns></returns>
        public static string SetCookieValueByName(string setCookie, string name, string value)
        {
            var regex = new Regex($"(?<={name}=).*?(?=; )");
            if (regex.IsMatch(setCookie)) setCookie = regex.Replace(setCookie, value);
            return setCookie;
        }

        /// <summary>
        ///     通过Name 更新Cookie
        /// </summary>
        /// <param name="oldCookie">原Cookie</param>
        /// <param name="newCookie">更新内容</param>
        /// <param name="name">名字</param>
        /// <returns></returns>
        public static string UpdateCookieValueByName(string oldCookie, string newCookie, string name)
        {
            var regex = new Regex($"(?<={name}=).*?[(?=; )|$]");
            if (regex.IsMatch(oldCookie) && regex.IsMatch(newCookie))
                oldCookie = regex.Replace(oldCookie, regex.Match(newCookie).Value);
            return oldCookie;
        }
    }


    /// <summary>    
    /// 对文件和文本数据进行Multipart形式的编码    
    /// </summary>    
    public class MultipartForm
    {
        private Encoding encoding;
        private MemoryStream ms;
        private string boundary;
        private byte[] formData;
        /// <summary>    
        /// 获取编码后的字节数组    
        /// </summary>    
        public byte[] FormData
        {
            get
            {
                if (formData == null)
                {
                    byte[] buffer = encoding.GetBytes("--" + this.boundary + "--\r\n");
                    ms.Write(buffer, 0, buffer.Length);
                    formData = ms.ToArray();
                }
                return formData;
            }
        }
        /// <summary>    
        /// 获取此编码内容的类型    
        /// </summary>    
        public string ContentType
        {
            get { return "application/x-www-form-urlencoded; charset=UTF-8"; }
        }
        /// <summary>    
        /// 获取或设置对字符串采用的编码类型    
        /// </summary>    
        public Encoding StringEncoding
        {
            set { encoding = value; }
            get { return encoding; }
        }
        /// <summary>    
        /// 实例化    
        /// </summary>    
        public MultipartForm()
        {
            boundary = string.Format("--{0}--", Guid.NewGuid());
            ms = new MemoryStream();
            encoding = Encoding.Default;
        }


        /// <summary>    
        /// 添加一个文件    
        /// </summary>    
        /// <param name="name">文件域名称</param>    
        /// <param name="filename">文件名</param>    
        /// <param name="fileData">文件二进制数据</param>    
        /// <param name="contentType">二进制数据大小</param>    
        public void AddByte(string name, string filename, byte[] fileData, string contentType)
        {
            if (fileData.Length <= 0)
            {
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("--{0}\r\n", this.boundary);
            sb.AppendFormat("Content-Disposition: form-data; name=\"{0}\";filename=\"{1}\"\r\n", name, filename);
            sb.AppendFormat("Content-Type: {0}\r\n", contentType);
            sb.Append("\r\n");
            byte[] buf = encoding.GetBytes(sb.ToString());
            ms.Write(buf, 0, buf.Length);
            ms.Write(fileData, 0, fileData.Length);
            byte[] crlf = encoding.GetBytes("\r\n");
            ms.Write(crlf, 0, crlf.Length);
        }

        /// <summary>    
        /// 添加字符串    
        /// </summary>    
        /// <param name="name">文本域名称</param>    
        /// <param name="value">文本值</param>    
        public void AddString(string name, string value)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("--{0}\r\n", this.boundary);
            sb.AppendFormat("Content-Disposition: form-data; name=\"{0}\"\r\n", name);
            sb.Append("\r\n");
            sb.AppendFormat("{0}\r\n", value);
            byte[] buf = encoding.GetBytes(sb.ToString());
            ms.Write(buf, 0, buf.Length);
        }

    }
}