package web

import (
	"bytes"
	"net/http"
	"strings"
)

// errorWriter turns the plain-text error responses of http.Error and the
// router (404, 405, ...) into a page in the panel's style.
type errorWriter struct {
	http.ResponseWriter
	s    *Server
	code int
	done bool
}

func (e *errorWriter) WriteHeader(code int) {
	if code >= 400 && strings.HasPrefix(e.Header().Get("Content-Type"), "text/plain") {
		e.code = code
		return
	}
	e.ResponseWriter.WriteHeader(code)
}

func (e *errorWriter) Write(b []byte) (int, error) {
	if e.code == 0 {
		return e.ResponseWriter.Write(b)
	}
	if !e.done {
		e.done = true
		e.page(string(bytes.TrimSpace(b)))
	}
	return len(b), nil
}

func (e *errorWriter) Unwrap() http.ResponseWriter { return e.ResponseWriter }

func (e *errorWriter) page(orig string) {
	title, text := "Hata", "İstek tamamlanamadı."
	switch e.code {
	case http.StatusNotFound:
		title, text = "Sayfa bulunamadı", "Aradığınız sayfa yok ya da bu sayfayı görme yetkiniz yok."
	case http.StatusMethodNotAllowed:
		title, text = "Bu adres böyle açılmaz", "Bu sayfaya bir formdan ulaşılır. Genel bakıştan devam edin."
	case http.StatusForbidden:
		title, text = "İstek reddedildi", "Güvenlik kontrolü geçilemedi. Oturumunuzun süresi dolmuş olabilir; sayfayı yenileyip tekrar deneyin."
	case http.StatusTooManyRequests:
		title, text = "Çok fazla deneme", "Çok sayıda hatalı giriş denemesi yapıldı. Birkaç dakika sonra tekrar deneyin."
	case http.StatusRequestEntityTooLarge:
		title, text = "İstek çok büyük", "Gönderilen form izin verilen boyutu aşıyor."
	case http.StatusInternalServerError:
		title, text = "Beklenmeyen hata", "Sunucuda bir hata oluştu ve servis kayıtlarına yazıldı."
	case http.StatusConflict:
		title = "İşlem yapılamadı"
		if orig != "" {
			text = orig
		}
	}
	h := e.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Del("Content-Length")
	e.ResponseWriter.WriteHeader(e.code)
	var buf bytes.Buffer
	if err := e.s.tpl.ExecuteTemplate(&buf, "error.html", map[string]any{"Code": e.code, "Title": title, "Text": text}); err != nil {
		_, _ = e.ResponseWriter.Write([]byte(title + "\n"))
		return
	}
	_, _ = e.ResponseWriter.Write(buf.Bytes())
}
