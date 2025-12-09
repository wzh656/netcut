package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log" // 必须引入
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 配置
var (
	DataDir  = "./data"
	Username = os.Getenv("AUTH_USER")
	Password = os.Getenv("AUTH_PASS")
	Port     = "8080"
	tmpl     *template.Template
)

// 权限模式枚举
const (
	ModeAdminOnly   = 0 // 仅管理员 (默认)
	ModePublicRead  = 1 // 公开只读
	ModePublicWrite = 2 // 公开读写
	ModePassRead    = 3 // 密码只读
	ModePassWrite   = 4 // 密码读写
)

type Meta struct {
	Mode        int    `json:"mode"`
	KeyPassword string `json:"key_password"`
}

type PageData struct {
	Key      string
	Content  string
	Files    []FileItem
	IsAdmin  bool
	CanWrite bool
	ShowPass bool
	Meta     Meta
}

type FileItem struct {
	Name string
	Size string
}

func main() {
	if err := os.MkdirAll(DataDir, 0755); err != nil {
		log.Fatalf("无法创建数据目录: %v", err)
	}

	var err error
	tmpl, err = template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	mux := http.NewServeMux()
	
	// API
	mux.HandleFunc("GET /download/{key}/{filename}", handleDownload)
	mux.HandleFunc("POST /{key}/text", handleSaveText)
	mux.HandleFunc("POST /{key}/upload", handleUpload)
	mux.HandleFunc("POST /{key}/delete", handleDeleteFile)
	mux.HandleFunc("POST /{key}/settings", handleSettings)
	mux.HandleFunc("POST /{key}/auth", handleKeyAuth)
	mux.HandleFunc("GET /{key}/login", handleAdminLogin)
	
	// Page
	mux.HandleFunc("GET /{key}", handleView)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/default", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	server := &http.Server{
		Addr:         ":" + Port,
		Handler:      mux,
		ReadTimeout:  0, // 允许大文件上传长时间保持连接
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 服务启动: http://localhost:%s", Port)
	log.Fatal(server.ListenAndServe())
}

// 核心权限判断
func getPermission(r *http.Request, key string) (bool, bool, bool, Meta) {
	metaFile := filepath.Join(DataDir, key+".meta")
	meta := Meta{Mode: ModeAdminOnly}
	if data, err := os.ReadFile(metaFile); err == nil {
		json.Unmarshal(data, &meta)
	}

	// 1. 判断 Admin
	isAdmin := false
	if Username != "" && Password != "" {
		user, pass, ok := r.BasicAuth()
		if ok && user == Username && pass == Password {
			isAdmin = true
		}
	} else {
		// 开发环境未设置密码则默认 Admin
		isAdmin = true 
	}

	if isAdmin {
		return true, true, true, meta
	}

	// 2. 判断 Guest Key Password
	hasKeyPass := false
	cookie, err := r.Cookie("auth_" + key)
	if err == nil && meta.KeyPassword != "" && cookie.Value == meta.KeyPassword {
		hasKeyPass = true
	}

	switch meta.Mode {
	case ModeAdminOnly:
		return false, false, false, meta
	case ModePublicRead:
		return true, false, false, meta
	case ModePublicWrite:
		return true, true, false, meta
	case ModePassRead:
		return hasKeyPass, false, false, meta
	case ModePassWrite:
		return hasKeyPass, hasKeyPass, false, meta
	}

	return false, false, false, meta
}

// ✅ 修复后的 handleView：不给权限就不读数据
func handleView(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" || strings.Contains(key, ".") {
		http.Error(w, "Invalid Key", http.StatusBadRequest)
		return
	}

	canRead, canWrite, isAdmin, meta := getPermission(r, key)

	// 🔥 新增逻辑：Admin 状态唤醒
	// 如果用户不是 Admin，但兜里揣着 "force_admin" 的 Cookie，说明他刚才登录过。
	// 此时服务器强制返回 401，逼迫浏览器把缓存的 Authorization 头交出来。
	_, cookieErr := r.Cookie("force_admin")
	if !isAdmin && cookieErr == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Reloading for Admin...", http.StatusUnauthorized)
		return
	}

	// 如果没有读权限，且模式是 AdminOnly，直接拦截弹窗
	if !canRead && meta.Mode == ModeAdminOnly {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var content string
	var fileItems []FileItem

	// 🔥 安全修复核心：只有当 canRead 为 true 时，才去磁盘读取数据
	if canRead {
		// 读取文本
		contentBytes, _ := os.ReadFile(filepath.Join(DataDir, key+".txt"))
		content = string(contentBytes)

		// 读取文件列表
		filesDir := filepath.Join(DataDir, key+"_files")
		os.MkdirAll(filesDir, 0755)
		entries, _ := os.ReadDir(filesDir)
		for _, e := range entries {
			if !e.IsDir() {
				info, _ := e.Info()
				fileItems = append(fileItems, FileItem{
					Name: e.Name(),
					Size: formatSize(info.Size()),
				})
			}
		}
		// 排序
		sort.Slice(fileItems, func(i, j int) bool {
			iInfo, _ := os.Stat(filepath.Join(filesDir, fileItems[i].Name))
			jInfo, _ := os.Stat(filepath.Join(filesDir, fileItems[j].Name))
			return iInfo.ModTime().After(jInfo.ModTime())
		})
	}

	// 脱敏处理，防止密码泄露给前端
	meta.KeyPassword = "" 

	data := PageData{
		Key:      key,
		Content:  content,   // 如果没权限，这里是空字符串 ""
		Files:    fileItems, // 如果没权限，这里是 nil
		IsAdmin:  isAdmin,
		CanWrite: canWrite,
		// 如果不可读，且不是Admin模式(即密码模式)，则通知前端显示模态框
		ShowPass: !canRead && (meta.Mode == ModePassRead || meta.Mode == ModePassWrite),
		Meta:     meta,
	}

	tmpl.Execute(w, data)
}

// 保存文本
func handleSaveText(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	_, canWrite, _, _ := getPermission(r, key)
	if !canWrite {
		jsonResponse(w, false, "无写入权限")
		return
	}
	body, _ := io.ReadAll(r.Body)
	os.WriteFile(filepath.Join(DataDir, key+".txt"), body, 0644)
	jsonResponse(w, true, "已保存")
}

// 流式上传 (修复内存问题)
func handleUpload(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	_, canWrite, _, _ := getPermission(r, key)
	if !canWrite {
		jsonResponse(w, false, "无写入权限")
		return
	}

	reader, err := r.MultipartReader()
	if err != nil {
		jsonResponse(w, false, "上传初始化失败")
		return
	}

	filesDir := filepath.Join(DataDir, key+"_files")
	os.MkdirAll(filesDir, 0755)

	count := 0
	for {
		part, err := reader.NextPart()
		if err == io.EOF { break }
		if part.FormName() == "file" && part.FileName() != "" {
			filename := filepath.Base(part.FileName())
			if _, err := os.Stat(filepath.Join(filesDir, filename)); err == nil {
				filename = fmt.Sprintf("%d_%s", time.Now().Unix(), filename)
			}
			dst, _ := os.Create(filepath.Join(filesDir, filename))
			io.Copy(dst, part)
			dst.Close()
			count++
		}
	}
	jsonResponse(w, true, "上传成功")
}

// 删除文件
func handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	_, canWrite, _, _ := getPermission(r, key)
	if !canWrite {
		jsonResponse(w, false, "无删除权限")
		return
	}
	
	var req struct { Filename string `json:"filename"` }
	json.NewDecoder(r.Body).Decode(&req)
	
	if req.Filename == "" || strings.Contains(req.Filename, "/") {
		jsonResponse(w, false, "非法文件名")
		return
	}
	os.Remove(filepath.Join(DataDir, key+"_files", req.Filename))
	jsonResponse(w, true, "删除成功")
}

// 设置修改
func handleSettings(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	_, _, isAdmin, _ := getPermission(r, key)
	if !isAdmin {
		jsonResponse(w, false, "需要管理员权限")
		return
	}

	var newMeta Meta
	if err := json.NewDecoder(r.Body).Decode(&newMeta); err != nil {
		jsonResponse(w, false, "参数错误")
		return
	}
	if newMeta.Mode != ModePassRead && newMeta.Mode != ModePassWrite {
		newMeta.KeyPassword = ""
	}
	data, _ := json.Marshal(newMeta)
	os.WriteFile(filepath.Join(DataDir, key+".meta"), data, 0644)
	jsonResponse(w, true, "设置已更新")
}

// 密码验证
func handleKeyAuth(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	var req struct { Password string `json:"password"` }
	json.NewDecoder(r.Body).Decode(&req)

	metaFile := filepath.Join(DataDir, key+".meta")
	var meta Meta
	if data, err := os.ReadFile(metaFile); err == nil {
		json.Unmarshal(data, &meta)
	}

	if meta.KeyPassword != "" && meta.KeyPassword == req.Password {
		http.SetCookie(w, &http.Cookie{
			Name:  "auth_" + key,
			Value: req.Password,
			Path:  "/",
			HttpOnly: true,
			MaxAge: 86400 * 30, // 30天
		})
		jsonResponse(w, true, "验证通过")
	} else {
		jsonResponse(w, false, "密码错误")
	}
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	// 先检查是否已经携带了正确的 Auth 头
	if Username != "" && Password != "" {
		user, pass, ok := r.BasicAuth()
		if ok && user == Username && pass == Password {
			http.SetCookie(w, &http.Cookie{
				Name:     "force_admin",
				Value:    "1",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   3600 * 24, // 1天内有效
			})

			// 认证成功，直接跳回剪贴板页面
			http.Redirect(w, r, "/"+key, http.StatusFound)
			return
		}
	}

	// 没带或者错了，才弹窗要求认证
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Login Required", http.StatusUnauthorized)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	canRead, _, _, _ := getPermission(r, key)
	// 下载接口也要鉴权！
	if !canRead {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	filename := r.PathValue("filename")
	
	// 强制下载
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	
	http.ServeFile(w, r, filepath.Join(DataDir, key+"_files", filename))
}

func formatSize(size int64) string {
	const unit = 1024
	if size < unit { return fmt.Sprintf("%d B", size) }
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func jsonResponse(w http.ResponseWriter, success bool, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": success, "msg": msg})
}