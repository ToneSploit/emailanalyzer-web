package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/tonesploit/emailanalyzer"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	maxBodySize = 25 << 20 // 25 MB
	resultTTL   = 30 * time.Minute
)

type entry struct {
	result    *emailanalyzer.Result
	markdown  string
	jsonBytes []byte
	filename  string
	expiresAt time.Time
}

var (
	store   = map[string]*entry{}
	storeMu sync.Mutex
)

func main() {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none'",
	}))
	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{Rate: 10, Burst: 20, ExpiresIn: time.Minute},
		),
		ErrorHandler: func(c echo.Context, err error) error {
			return c.String(http.StatusTooManyRequests, "rate limit exceeded")
		},
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return c.String(http.StatusTooManyRequests, "rate limit exceeded")
		},
	}))
	e.Use(middleware.BodyLimit("25M"))

	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"b64decode": func(s string) string {
			if s == "" {
				return ""
			}
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return ""
			}
			return string(b)
		},
		"fmtdur": emailanalyzer.FormatDuration,
		"parsedate": func(s string) string {
			if t := emailanalyzer.ParseReceivedDate(s); !t.IsZero() {
				return t.Format(time.RFC3339)
			}
			return s
		},
		"authbadge": func(result string) template.HTML {
			switch strings.ToLower(result) {
			case "pass":
				return `<span class="badge pass">PASS</span>`
			case "fail", "permerror", "temperror", "hardfail":
				return template.HTML(`<span class="badge fail">FAIL (` + template.HTMLEscapeString(result) + `)</span>`)
			case "softfail":
				return `<span class="badge soft">SOFTFAIL</span>`
			case "neutral":
				return `<span class="badge none">NEUTRAL</span>`
			case "none", "":
				return `<span class="badge none">NONE</span>`
			default:
				return template.HTML(`<span class="badge none">` + template.HTMLEscapeString(result) + `</span>`)
			}
		},
		"boolflag": func(b bool) template.HTML {
			if b {
				return `<span class="flag-yes">YES</span>`
			}
			return `<span class="flag-no">no</span>`
		},
		"inc": func(i int) int { return i + 1 },
	}).ParseFS(templateFS, "templates/*.html"))

	e.GET("/", func(c echo.Context) error {
		return tmpl.ExecuteTemplate(c.Response(), "index.html", nil)
	})

	e.POST("/analyze", func(c echo.Context) error {
		c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxBodySize)

		fh, err := c.FormFile("email")
		if err != nil {
			return c.String(http.StatusBadRequest, "missing file")
		}

		ext := strings.ToLower(filepath.Ext(fh.Filename))
		if ext != ".eml" && ext != ".msg" && ext != ".txt" {
			return c.String(http.StatusBadRequest, "only .eml / .msg / .txt files accepted")
		}

		src, err := fh.Open()
		if err != nil {
			return c.String(http.StatusInternalServerError, "could not open upload")
		}
		defer src.Close()

		result, err := emailanalyzer.Analyze(src, sanitize(fh.Filename))
		if err != nil {
			return c.String(http.StatusBadRequest, "could not parse email: "+err.Error())
		}

		md := emailanalyzer.ToMarkdown(result)
		jb, _ := json.MarshalIndent(result, "", "  ")

		id := result.Metadata.FileHash[:32]
		storeMu.Lock()
		store[id] = &entry{
			result:    result,
			markdown:  md,
			jsonBytes: jb,
			filename:  sanitize(fh.Filename),
			expiresAt: time.Now().Add(resultTTL),
		}
		storeMu.Unlock()

		go reap()

		return c.Redirect(http.StatusSeeOther, "/result/"+id)
	})

	e.GET("/result/:id", func(c echo.Context) error {
		ent, ok := getEntry(c.Param("id"))
		if !ok {
			return c.String(http.StatusNotFound, "result not found or expired")
		}
		buf := &bytes.Buffer{}
		if err := tmpl.ExecuteTemplate(buf, "result.html", ent.result); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.HTMLBlob(http.StatusOK, buf.Bytes())
	})

	e.GET("/result/:id/download/json", func(c echo.Context) error {
		ent, ok := getEntry(c.Param("id"))
		if !ok {
			return c.String(http.StatusNotFound, "not found")
		}
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, stem(ent.filename)))
		return c.Blob(http.StatusOK, "application/json", ent.jsonBytes)
	})

	e.GET("/result/:id/download/md", func(c echo.Context) error {
		ent, ok := getEntry(c.Param("id"))
		if !ok {
			return c.String(http.StatusNotFound, "not found")
		}
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.md"`, stem(ent.filename)))
		return c.Blob(http.StatusOK, "text/markdown; charset=utf-8", []byte(ent.markdown))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	e.Logger.Fatal(e.Start(":" + port))
}

var reUnsafe = regexp.MustCompile(`[^a-zA-Z0-9._\- ]`)

func sanitize(name string) string {
	name = filepath.Base(name)
	name = reUnsafe.ReplaceAllString(name, "_")
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

func stem(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func getEntry(id string) (*entry, bool) {
	if !reID.MatchString(id) {
		return nil, false
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	ent, ok := store[id]
	if !ok || time.Now().After(ent.expiresAt) {
		delete(store, id)
		return nil, false
	}
	return ent, true
}

func reap() {
	storeMu.Lock()
	defer storeMu.Unlock()
	now := time.Now()
	for k, v := range store {
		if now.After(v.expiresAt) {
			delete(store, k)
		}
	}
}
