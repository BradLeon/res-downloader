package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	DownloadStatusReady   string = "ready" // task create but not start
	DownloadStatusRunning string = "running"
	DownloadStatusError   string = "error"
	DownloadStatusDone    string = "done"
	DownloadStatusHandle  string = "handle"
)

type WxFileDecodeResult struct {
	SavePath string
	Message  string
}

type Resource struct {
	mediaMark sync.Map
	resType   map[string]bool
	resTypeMu sync.RWMutex
}

func initResource() *Resource {
	if resourceOnce == nil {
		resourceOnce = &Resource{
			resType: map[string]bool{
				"all":   true,
				"image": true,
				"audio": true,
				"video": true,
				"m3u8":  true,
				"live":  true,
				"xls":   true,
				"doc":   true,
				"pdf":   true,
			},
		}
	}
	return resourceOnce
}

func (r *Resource) mediaIsMarked(key string) bool {
	_, loaded := r.mediaMark.Load(key)
	return loaded
}

func (r *Resource) markMedia(key string) {
	r.mediaMark.Store(key, true)
}

func (r *Resource) getResType(key string) (bool, bool) {
	r.resTypeMu.RLock()
	defer r.resTypeMu.RUnlock()
	value, ok := r.resType[key]
	return value, ok
}

func (r *Resource) setResType(n []string) {
	r.resTypeMu.Lock()
	defer r.resTypeMu.Unlock()
	r.resType = map[string]bool{
		"all":   false,
		"image": false,
		"audio": false,
		"video": false,
		"m3u8":  false,
		"live":  false,
		"xls":   false,
		"doc":   false,
		"pdf":   false,
	}

	for _, value := range n {
		r.resType[value] = true
	}
}

func (r *Resource) clear() {
	r.mediaMark.Clear()
}

func (r *Resource) delete(sign string) {
	r.mediaMark.Delete(sign)
}

func (r *Resource) download(mediaInfo MediaInfo, decodeStr string) {
	if globalConfig.SaveDirectory == "" {
		return
	}

	go func(mediaInfo MediaInfo) {
		rawUrl := mediaInfo.Url
		fileName := Md5(rawUrl)
		if mediaInfo.Description != "" {
			fileName = regexp.MustCompile(`[^\w\p{Han}]`).ReplaceAllString(mediaInfo.Description, "")
			fileLen := globalConfig.FilenameLen
			if fileLen <= 0 {
				fileLen = 10
			}

			runes := []rune(fileName)
			if len(runes) > fileLen {
				fileName = string(runes[:fileLen])
			}
		}

		if globalConfig.FilenameTime {
			mediaInfo.SavePath = filepath.Join(globalConfig.SaveDirectory, fileName+"_"+GetCurrentDateTimeFormatted()+mediaInfo.Suffix)
		} else {
			mediaInfo.SavePath = filepath.Join(globalConfig.SaveDirectory, fileName+mediaInfo.Suffix)
		}
		globalLogger.Info().Msgf("[resource.go download] mediaInfo.SavePath: %v", mediaInfo.SavePath)
		globalLogger.Info().Msgf("[resource.go download] rawUrl: %v", rawUrl)

		if strings.Contains(rawUrl, "qq.com") {
			if globalConfig.Quality == 1 &&
				strings.Contains(rawUrl, "encfilekey=") &&
				strings.Contains(rawUrl, "token=") {
				parseUrl, err := url.Parse(rawUrl)
				queryParams := parseUrl.Query()
				if err == nil && queryParams.Has("encfilekey") && queryParams.Has("token") {
					rawUrl = parseUrl.Scheme + "://" + parseUrl.Host + "/" + parseUrl.Path +
						"?encfilekey=" + queryParams.Get("encfilekey") +
						"&token=" + queryParams.Get("token")
				}
				globalLogger.Info().Msgf("[resource.go download] globalConfig.Quality == 1 parseUrl: %v", parseUrl)
				globalLogger.Info().Msgf("[resource.go download] globalConfig.Quality == 1 queryParams: %v", queryParams)
				globalLogger.Info().Msgf("[resource.go download] globalConfig.Quality == 1 rawUrl: %v", rawUrl)

			} else if globalConfig.Quality > 1 && mediaInfo.OtherData["wx_file_formats"] != "" {
				format := strings.Split(mediaInfo.OtherData["wx_file_formats"], "#")
				qualityMap := []string{
					format[0],
					format[len(format)/2],
					format[len(format)-1],
				}
				rawUrl += "&X-snsvideoflag=" + qualityMap[globalConfig.Quality-2]

				globalLogger.Info().Msgf("[resource.go download] globalConfig.Quality > 1 format: %v", mediaInfo.OtherData["wx_file_formats"])
				globalLogger.Info().Msgf("[resource.go download] globalConfig.Quality > 1 rawUrl: %v", rawUrl)
			}
		}

		headers, _ := r.parseHeaders(mediaInfo)

		globalLogger.Info().Msgf("[resource.go download] after parseHeaders headers: %v", headers)

		downloader := NewFileDownloader(rawUrl, mediaInfo.SavePath, globalConfig.TaskNumber, headers)
		downloader.progressCallback = func(totalDownloaded float64) {
			r.progressEventsEmit(mediaInfo, strconv.Itoa(int(totalDownloaded))+"%", DownloadStatusRunning)
		}
		err := downloader.Start()
		if err != nil {
			r.progressEventsEmit(mediaInfo, err.Error())
			return
		}
		if decodeStr != "" {
			r.progressEventsEmit(mediaInfo, "解密中", DownloadStatusRunning)
			if err := r.decodeWxFile(mediaInfo.SavePath, decodeStr); err != nil {
				r.progressEventsEmit(mediaInfo, "解密出错"+err.Error())
				return
			}
		}
		r.progressEventsEmit(mediaInfo, "完成", DownloadStatusDone)
	}(mediaInfo)
}

// 解析并组装 headers
func (r *Resource) parseHeaders(mediaInfo MediaInfo) (map[string]string, error) {
	headers := make(map[string]string)

	if hh, ok := mediaInfo.OtherData["headers"]; ok {
		var tempHeaders map[string][]string
		// 解析 JSON 字符串为 map[string][]string
		if err := json.Unmarshal([]byte(hh), &tempHeaders); err != nil {
			return headers, fmt.Errorf("parse headers JSON err: %v", err)
		}

		for key, values := range tempHeaders {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}
	}

	return headers, nil
}

func (r *Resource) wxFileDecode(mediaInfo MediaInfo, fileName, decodeStr string) (string, error) {
	globalLogger.Info().Msgf("enter [resource.go wxFileDecode] 3 params, fileName: %v, decodeStr: %v", fileName, decodeStr)
	sourceFile, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer sourceFile.Close()
	mediaInfo.SavePath = strings.ReplaceAll(fileName, ".mp4", "_解密.mp4")

	destinationFile, err := os.Create(mediaInfo.SavePath)
	if err != nil {
		return "", err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return "", err
	}
	err = r.decodeWxFile(mediaInfo.SavePath, decodeStr)
	if err != nil {
		return "", err
	}
	globalLogger.Info().Msgf("success exit [resource.go wxFileDecode] 3 params, fileName: %v, decodeStr: %v", mediaInfo.SavePath, decodeStr)
	return mediaInfo.SavePath, nil
}

func (r *Resource) progressEventsEmit(mediaInfo MediaInfo, args ...string) {
	Status := DownloadStatusError
	Message := "ok"

	if len(args) > 0 {
		Message = args[0]
	}
	if len(args) > 1 {
		Status = args[1]
	}

	httpServerOnce.send("downloadProgress", map[string]interface{}{
		"Id":       mediaInfo.Id,
		"Status":   Status,
		"SavePath": mediaInfo.SavePath,
		"Message":  Message,
	})
	return
}

func (r *Resource) decodeWxFile(fileName, decodeStr string) error {
	// 第1步：将base64编码的字符串解码为字节数组
	// 这里decodeStr是一个base64编码的密钥，需要先解码才能使用
	globalLogger.Info().Msgf("enter [resource.go decodeWxFile] fileName: %v, decodeStr: %v", fileName, decodeStr)
	decodedBytes, err := base64.StdEncoding.DecodeString(decodeStr)
	if err != nil {
		return err
	}

	// 第2步：以读写模式打开要解密的文件
	// O_RDWR表示以读写模式打开，0644是文件权限（所有者可读写，其他人只读）
	file, err := os.OpenFile(fileName, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	// 确保函数结束时关闭文件，防止资源泄漏
	defer file.Close()

	// 第3步：获取解码后密钥的长度，并创建相同大小的缓冲区
	byteCount := len(decodedBytes)
	fileBytes := make([]byte, byteCount)

	// 第4步：从文件开头读取与密钥长度相同的字节数
	// 这里只读取文件的前byteCount个字节，因为微信文件加密通常只加密文件头部
	_, err = file.Read(fileBytes)
	if err != nil && err != io.EOF {
		return err
	}

	// 第5步：执行XOR（异或）操作进行解密
	// XOR是一种常见的加密/解密方法，对同一数据执行两次XOR操作会还原原始数据
	// 这里对文件的前byteCount个字节与密钥进行异或操作
	xorResult := make([]byte, byteCount)
	for i := 0; i < byteCount; i++ {
		xorResult[i] = decodedBytes[i] ^ fileBytes[i]
	}

	// 第6步：将文件指针重新定位到文件开头
	// Seek(0, 0)表示从文件开头（第二个0）偏移0个字节（第一个0）
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}

	// 第7步：将解密后的数据写回文件
	// 这会覆盖文件开头的加密数据，完成解密过程
	_, err = file.Write(xorResult)
	if err != nil {
		return err
	}

	globalLogger.Info().Msgf("success exit [resource.go decodeWxFile] fileName: %v, decodeStr: %v", fileName, decodeStr)

	// 解密成功，返回nil表示没有错误
	return nil
}
