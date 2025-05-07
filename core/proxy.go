package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

type Proxy struct {
	ctx   context.Context
	Proxy *goproxy.ProxyHttpServer
	Is    bool
}

type MediaInfo struct {
	Id          string
	Url         string
	UrlSign     string
	CoverUrl    string
	Size        string
	Domain      string
	Classify    string
	Suffix      string
	SavePath    string
	Status      string
	DecodeKey   string
	Description string
	ContentType string
	OtherData   map[string]string
}

func initProxy() *Proxy {
	if proxyOnce == nil {
		proxyOnce = &Proxy{}
		proxyOnce.Startup()
	}
	return proxyOnce
}

func (p *Proxy) Startup() {
	err := p.setCa()
	if err != nil {
		DialogErr("启动代理服务失败：" + err.Error())
		return
	}

	p.Proxy = goproxy.NewProxyHttpServer()
	//p.Proxy.KeepDestinationHeaders = true
	//p.Proxy.Verbose = false
	p.setTransport()
	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	p.Proxy.OnRequest().DoFunc(p.httpRequestEvent)
	p.Proxy.OnResponse().DoFunc(p.httpResponseEvent)
}

func (p *Proxy) setCa() error {
	ca, err := tls.X509KeyPair(appOnce.PublicCrt, appOnce.PrivateKey)
	if err != nil {
		DialogErr("启动代理服务失败1")
		return err
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	return nil
}

func (p *Proxy) setTransport() {
	transport := &http.Transport{
		DisableKeepAlives: false,
		// MaxIdleConnsPerHost: 10,
		DialContext: (&net.Dialer{
			Timeout: 60 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}

	if globalConfig.UpstreamProxy != "" && globalConfig.OpenProxy && !strings.Contains(globalConfig.UpstreamProxy, globalConfig.Port) {
		proxyURL, err := url.Parse(globalConfig.UpstreamProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	p.Proxy.Tr = transport
}

func (p *Proxy) httpRequestEvent(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if strings.Contains(r.Host, "res-downloader.666666.com") && strings.Contains(r.URL.Path, "/wechat") {
		globalLogger.Info().Msg("进入 wechat 转发 request")
		globalLogger.Info().Msgf("请求地址：%s", r.URL.String())
		globalLogger.Info().Msgf("请求头：%v", r.Header)

		if globalConfig.WxAction && r.URL.Query().Get("type") == "1" {
			globalLogger.Info().Msg("进入 wechat 转发 request 1")
			return p.handleWechatRequest(r, ctx)
		} else if !globalConfig.WxAction && r.URL.Query().Get("type") == "2" {
			globalLogger.Info().Msg("进入 wechat 转发 request 2")
			return p.handleWechatRequest(r, ctx)
		} else {
			globalLogger.Info().Msg("进入 wechat 转发 request 3")
			return r, p.buildEmptyResponse(r)
		}
	}
	return r, nil
}

func (p *Proxy) handleWechatRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return r, p.buildEmptyResponse(r)
	}
	globalLogger.Info().Msg("Enter handleWechatRequest!")
	globalLogger.Info().Msgf("[handleWechatRequest] host: %s, Path: %s", r.Host, r.URL.Path)
	isAll, _ := resourceOnce.getResType("all")
	isClassify, _ := resourceOnce.getResType("video")
	globalLogger.Info().Msgf("[handleWechatRequest] request body: %s", string(body))
	globalLogger.Info().Msgf("[handleWechatRequest] isAll: %v, isClassify: %v", isAll, isClassify)

	if !isAll && !isClassify {
		return r, p.buildEmptyResponse(r)
	}
	go func(body []byte) {
		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err != nil {
			return
		}
		media, ok := result["media"].([]interface{})
		if !ok || len(media) <= 0 {
			return
		}
		firstMedia, ok := media[0].(map[string]interface{})
		if !ok {
			return
		}
		rowUrl, ok := firstMedia["url"]
		if !ok {
			return
		}

		urlSign := Md5(rowUrl.(string))
		if resourceOnce.mediaIsMarked(urlSign) {
			return
		}

		id, err := gonanoid.New()
		if err != nil {
			id = urlSign
		}
		res := MediaInfo{
			Id:          id,
			Url:         rowUrl.(string),
			UrlSign:     urlSign,
			CoverUrl:    "",
			Size:        "0",
			Domain:      GetTopLevelDomain(rowUrl.(string)),
			Classify:    "video",
			Suffix:      ".mp4",
			Status:      DownloadStatusReady,
			SavePath:    "",
			DecodeKey:   "",
			OtherData:   map[string]string{},
			Description: "",
			ContentType: "video/mp4",
		}

		if mediaType, ok := firstMedia["mediaType"].(float64); ok && mediaType == 9 {
			res.Classify = "image"
			res.Suffix = ".png"
			res.ContentType = "image/png"
		}

		if urlToken, ok := firstMedia["urlToken"].(string); ok {
			res.Url = res.Url + urlToken
		}
		if fileSize, ok := firstMedia["fileSize"].(float64); ok {
			res.Size = FormatSize(fileSize)
		}
		if coverUrl, ok := firstMedia["coverUrl"].(string); ok {
			res.CoverUrl = coverUrl
		}
		if fileSize, ok := firstMedia["fileSize"].(string); ok {
			value, err := strconv.ParseFloat(fileSize, 64)
			if err == nil {
				res.Size = FormatSize(value)
			}
		}
		if decodeKey, ok := firstMedia["decodeKey"].(string); ok {
			res.DecodeKey = decodeKey
			globalLogger.Info().
				Str("decodeKey", decodeKey).
				Str("urlSign", urlSign).
				Msg("[handleWechatRequest] 微信视频发现解密密钥")
		}
		if desc, ok := result["description"].(string); ok {
			res.Description = desc
		}
		if spec, ok := firstMedia["spec"].([]interface{}); ok {
			var fileFormats []string
			for _, item := range spec {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if format, exists := itemMap["fileFormat"].(string); exists {
						fileFormats = append(fileFormats, format)
					}
				}
			}

			res.OtherData["wx_file_formats"] = strings.Join(fileFormats, "#")
		}

		globalLogger.Info().Interface("res", res).Msg("[handleWechatRequest] res")

		resourceOnce.markMedia(urlSign)
		// httpServerOnce.send() 用于将新发现的资源通知前端UI
		// 如果没有这行代码,前端将无法实时显示新发现的资源
		// 因为前端依赖这个事件来更新资源列表
		// todo(lutong)，这里前后端交互， 如果后续包装成后端pipeline，就不需要回传前端了。
		httpServerOnce.send("newResources", res)
		// Backend: emits "newResources" event via runtime.EventsEmit；后端：通过 runtime.EventsEmit 发送 "newResources" 事件到前端
		// Frontend: eventStore.addHandle("newResources") will push res to data.value, update localStorage("resources-data"), refresh UI resources list,
		// then user actions (e.g., download, openFolder) trigger subsequent logic in dataAction and downloadProgress handlers；前端：eventStore.addHandle("newResources") 会将 res 推入 data.value，更新 localStorage，刷新 UI 列表，随后用户操作（下载、打开文件夹）将触发 dataAction 和 downloadProgress 等后续逻辑

		// 拦截的是前端发给微信 API 的 POST 请求（/wechat?type=1/2），从请求体里直接解析出媒体资源的元信息（URL、fileSize、decodeKey 等）。
		// 先一步将嗅探到的资源快速呈现给前端，让用户尽早看到可下载列表。
		// 执行 resourceOnce.markMedia(urlSign)，并立即 send("newResources", res)。
	}(body)
	return r, p.buildEmptyResponse(r)
}

func (p *Proxy) buildEmptyResponse(r *http.Request) *http.Response {
	body := "内容不存在"
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}
	resp.Header.Set("Content-Type", "text/plain")
	return resp
}

func (p *Proxy) httpResponseEvent(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	globalLogger.Info().Msg("Enter httpResponseEvent!")
	if resp == nil || resp.Request == nil || (resp.StatusCode != 200 && resp.StatusCode != 206) {
		return resp
	}

	host := resp.Request.Host
	Path := resp.Request.URL.Path
	url := resp.Request.URL.String()
	// 自动筛查所有经过代理的 JS 文件请求
	if strings.HasSuffix(strings.ToLower(Path), ".js") || strings.Contains(strings.ToLower(Path), ".js?") {
		globalLogger.Info().
			Str("host", host).
			Str("path", Path).
			Str("url", url).
			Msg("[JS筛查] 发现JS文件请求")
	}

	globalLogger.Info().
		Str("host", host).
		Str("path", Path).
		Msg("[httpResponseEvent] 检查响应")

	// 这段代码针对微信资源页面的 JavaScript 文件进行中间人注入（MITM injection）
	//.js" → .js?v=版本号" 强制浏览器下载最新脚本而非使用缓存，使我们注入的代码始终生效，避免缓存问题
	if strings.HasSuffix(host, "channels.weixin.qq.com") &&
		(strings.Contains(Path, "/web/pages/feed") || strings.Contains(Path, "/web/pages/home")) {
		globalLogger.Info().Msg("[httpResponseEvent]进入 wechat 转发 response 1")
		return p.replaceWxJsContent(resp, ".js\"", ".js?v="+p.v()+"\"")
	}

	// 特定条件（微信视频组件JS）下，注入两段监听代码：
	if strings.HasSuffix(host, "res.wx.qq.com") {
		respTemp := resp
		is := false
		if strings.HasSuffix(respTemp.Request.URL.RequestURI(), ".js?v="+p.v()) {
			globalLogger.Info().Msg("[httpResponseEvent]进入 wechat 转发 response 2")
			respTemp = p.replaceWxJsContent(respTemp, ".js\"", ".js?v="+p.v()+"\"")
			is = true
			globalLogger.Info().Msgf("[httpResponseEvent] after replaceWxJsContent respTemp: %v", respTemp)
		}

		// 这get media、finderGetCommentDetail 两个函数是通过逆向工程微信频道/视频号网页版JavaScript发现的关键点：
		if strings.Contains(Path, "web/web-finder/res/js/virtual_svg-icons-register.publish") {
			globalLogger.Info().Msg("[httpResponseEvent]进入 wechat 转发 response 3")
			body, err := io.ReadAll(respTemp.Body)
			if err != nil {
				return respTemp
			}
			bodyStr := string(body)
			newBody := regexp.MustCompile(`get\s*media\(\)\{`).
				ReplaceAllString(bodyStr, `
							get media(){
								if(this.objectDesc){
									fetch("https://res-downloader.666666.com/wechat?type=1", {
									  method: "POST",
									  mode: "no-cors",
									  body: JSON.stringify(this.objectDesc),
									});
								};
			
			`)
			globalLogger.Info().Msgf("[httpResponseEvent] after replaceWxJsContent newBody 1: %s", newBody)

			newBody = regexp.MustCompile(`async\s*finderGetCommentDetail\((\w+)\)\s*\{return(.*?)\s*}\s*async`).
				ReplaceAllString(newBody, `
							async finderGetCommentDetail($1) {
								var res = await$2;
								if (res?.data?.object?.objectDesc) {
									fetch("https://res-downloader.666666.com/wechat?type=2", {
									  method: "POST",
									  mode: "no-cors",
									  body: JSON.stringify(res.data.object.objectDesc),
									});
								}
								return res;
							}async
			`)
			globalLogger.Info().Msgf("[httpResponseEvent] after replaceWxJsContent newBody 2: %s", newBody)

			// 二、被注入后的执行逻辑
			// Execution Flow After Injection
			// 代理将修改后的JS返回给浏览器
			// 用户访问微信视频页面，加载的JS已被我们注入了额外代码
			// 用户浏览视频或评论时触发注入代码
			// 当微信原始JS执行到 get media() 或 finderGetCommentDetail 时
			// 触发注入的 fetch() 请求，将资源描述信息发送到虚拟域名
			// 这些请求被自动路由到代理
			// 域名 res-downloader.666666.com 被默认路由到我们的代理
			// 然后进入 httpRequestEvent → handleWechatRequest 函数
			// 资源提取与前端推送
			// 代理解析请求体中的 mediaDesc 数据，提取资源URL、大小等信息
			// 创建 MediaInfo 对象并标记该资源（markMedia）
			// 推送给前端界面（httpServerOnce.send("newResources", res)）
			// 前端界面展示可下载资源
			// 前端收到嗅探到的资源，展示给用户，用户可点击下载

			// Go 的 HTTP Response.Body 类型是 io.ReadCloser，不是字符串或字节数组
			// 不能直接赋值字符串／字节数组给 Response.Body，因为类型不匹配
			// 必须用 io.NopCloser 包裹一个实现了 io.Reader 的对象，满足 io.ReadCloser
			// 同时要更新 Content-Length，保证客户端完整接收修改后数据
			newBodyBytes := []byte(newBody)
			respTemp.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))
			respTemp.ContentLength = int64(len(newBodyBytes))
			respTemp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBodyBytes)))
			return respTemp
		}
		if is {
			return respTemp
		}
	}

	classify, suffix := TypeSuffix(resp.Header.Get("Content-Type"))
	if classify == "" {
		globalLogger.Info().Msg("[httpResponseEvent] classify is empty，return org resp")
		return resp
	}

	if classify == "video" && strings.HasSuffix(host, "finder.video.qq.com") {
		//if !globalConfig.WxAction && classify == "video" && strings.HasSuffix(host, "finder.video.qq.com") {
		globalLogger.Info().Msg("[httpResponseEvent] classify is video and host is finder.video.qq.com, return org resp")
		return resp
	}

	rawUrl := resp.Request.URL.String()
	isAll, _ := resourceOnce.getResType("all")
	isClassify, _ := resourceOnce.getResType(classify)

	urlSign := Md5(rawUrl)
	if ok := resourceOnce.mediaIsMarked(urlSign); !ok && (isAll || isClassify) {
		// 只有未标记时才 send / mark
		value, _ := strconv.ParseFloat(resp.Header.Get("content-length"), 64)
		id, err := gonanoid.New()
		if err != nil {
			id = urlSign
		}
		res := MediaInfo{
			Id:          id,
			Url:         rawUrl,
			UrlSign:     urlSign,
			CoverUrl:    "",
			Size:        FormatSize(value),
			Domain:      GetTopLevelDomain(rawUrl),
			Classify:    classify,
			Suffix:      suffix,
			Status:      DownloadStatusReady,
			SavePath:    "",
			DecodeKey:   "",
			OtherData:   map[string]string{},
			Description: "",
			ContentType: resp.Header.Get("Content-Type"),
		}

		// Store entire request headers as JSON
		if headers, err := json.Marshal(resp.Request.Header); err == nil {
			res.OtherData["headers"] = string(headers)
		}
		globalLogger.Info().Interface("res", res).Msg("[httpResponseEvent] res")
		// 拦截的是 HTTP 响应，针对所有媒体类型（视频、图片、音频、m3u8……）的实际流请求或资源文件。
		// 从响应头（Content‐Length、Content‐Type、请求头）里补全更准确的资源信息（真实大小、headers）。
		// 同样做 markMedia + send("newResources", res)，但只有当该资源 未被标记 时才会执行。
		// 为什么需要两次嗅探 / Why Two Sniffing Steps
		// 提前展示：先从微信 JSON 接口解析出资源，尽快在界面展现下载按钮。
		// 数据补全：再从 HTTP 响应中获取真实的大小和必要的请求头，方便下载器精确下载。
		// 两个步骤互补，标记机制保证不会发两次相同消息。
		resourceOnce.markMedia(urlSign)
		httpServerOnce.send("newResources", res)
	}
	return resp
}

func (p *Proxy) replaceWxJsContent(resp *http.Response, old, new string) *http.Response {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp
	}
	bodyString := string(body)
	newBodyString := strings.ReplaceAll(bodyString, old, new)
	newBodyBytes := []byte(newBodyString)
	resp.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))
	resp.ContentLength = int64(len(newBodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBodyBytes)))
	return resp
}

func (p *Proxy) v() string {
	return appOnce.Version
}
