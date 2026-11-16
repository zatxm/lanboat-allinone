package native

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func sudokuPrefixURL(value, prefix string) string {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return value
	}
	end := strings.IndexAny(value, "?#")
	if end < 0 {
		end = len(value)
	}
	if sudokuReversePath(value[:end], prefix) {
		return value
	}
	return prefix + value
}

func sudokuReverseHeaders(resp *http.Response, prefix string) {
	if value := resp.Header.Get("Location"); value != "" {
		if u, err := url.Parse(value); err == nil {
			local := u.Host == "" && u.Scheme == "" || (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, resp.Request.Host)
			if local && !strings.HasPrefix(value, "//") {
				u.Path = sudokuPrefixURL(u.Path, prefix)
				u.RawPath = ""
				if u.Host != "" {
					u.Scheme, u.Host = "", ""
				}
				resp.Header.Set("Location", u.String())
			}
		}
	}
	cookies := resp.Header.Values("Set-Cookie")
	resp.Header.Del("Set-Cookie")
	for _, value := range cookies {
		parts := strings.Split(value, ";")
		for i := 1; i < len(parts); i++ {
			key, value, ok := strings.Cut(strings.TrimSpace(parts[i]), "=")
			if ok && strings.EqualFold(key, "path") {
				parts[i] = " Path=" + sudokuPrefixURL(value, prefix)
			}
		}
		resp.Header.Add("Set-Cookie", strings.Join(parts, ";"))
	}
	resp.Header.Add("Set-Cookie", (&http.Cookie{Name: sudokuReverseCookie, Value: url.PathEscape(prefix), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}).String())
}

const sudokuReverseBodyLimit = 1 << 20

type sudokuReverseBodyReader struct {
	io.Reader
	io.Closer
}

func sudokuReverseBodyType(resp *http.Response) string {
	if resp.Request.Method == "HEAD" || resp.StatusCode == 206 || resp.Header.Get("Content-Range") != "" || resp.ContentLength > sudokuReverseBodyLimit {
		return ""
	}
	if ext := strings.ToLower(path.Ext(resp.Request.URL.Path)); ext == ".js" || ext == ".mjs" {
		return ""
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == "" {
		switch strings.ToLower(path.Ext(resp.Request.URL.Path)) {
		case ".html", ".htm":
			ct = "text/html"
		case ".css":
			ct = "text/css"
		case ".svg":
			ct = "image/svg+xml"
		case ".json", ".webmanifest":
			ct = "application/json"
		}
	}
	if ct != "text/html" && ct != "application/xhtml+xml" && ct != "image/svg+xml" && ct != "text/css" && ct != "application/json" && ct != "application/manifest+json" {
		return ""
	}
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		return ""
	}
	return ct
}

func sudokuReverseBody(resp *http.Response, prefix string) error {
	ct := sudokuReverseBodyType(resp)
	if ct == "" {
		return nil
	}
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	raw, err := io.ReadAll(io.LimitReader(resp.Body, sudokuReverseBodyLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > sudokuReverseBodyLimit {
		resp.Body = sudokuReverseBodyReader{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	setBody := func(data []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
	}
	setBody(raw)
	data := raw
	if encoding == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil
		}
		data, err = io.ReadAll(io.LimitReader(reader, sudokuReverseBodyLimit+1))
		reader.Close()
		if err != nil || len(data) > sudokuReverseBodyLimit {
			return nil
		}
	}
	updated := sudokuRewriteText(data, prefix, ct)
	if !bytes.Equal(updated, data) {
		setBody(updated)
		for _, key := range []string{"Content-Encoding", "ETag", "Content-MD5", "Digest", "Accept-Ranges"} {
			resp.Header.Del(key)
		}
	}
	return nil
}

// Parse URL-bearing markup instead of replacing arbitrary /strings in inline
// scripts,comments or ordinary text. JavaScript and streaming bodies stay opaque.
func sudokuRewriteText(data []byte, prefix, contentType string) []byte {
	var out []byte
	last := 0
	overflow := false
	insert := func(position int) {
		if position < last || len(out)+position-last+len(prefix) > 2*sudokuReverseBodyLimit {
			overflow = true
			return
		}
		if out == nil {
			out = make([]byte, 0, min(len(data)+256, 2*sudokuReverseBodyLimit))
		}
		out = append(out, data[last:position]...)
		out = append(out, prefix...)
		last = position
	}
	root := func(start, end int) {
		if start < end && data[start] == '/' && sudokuPrefixURL(string(data[start:end]), prefix) != string(data[start:end]) {
			insert(start)
		}
	}
	space := func(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' }
	css := func(start, end int) {
		for i := start; i+4 < end; i++ {
			if (data[i] != 'u' && data[i] != 'U') || !strings.EqualFold(string(data[i:i+3]), "url") {
				continue
			}
			j := i + 3
			for j < end && space(data[j]) {
				j++
			}
			if j == end || data[j] != '(' {
				continue
			}
			j++
			for j < end && space(data[j]) {
				j++
			}
			if j < end && (data[j] == '\'' || data[j] == '"') {
				j++
			}
			k := j
			for k < end && !space(data[k]) && !strings.ContainsRune("'\")", rune(data[k])) {
				k++
			}
			root(j, k)
			i = k
		}
	}
	switch contentType {
	case "application/json", "application/manifest+json":
		for i := 0; i < len(data); i++ {
			if data[i] != '"' {
				continue
			}
			start := i + 1
			for i++; i < len(data); i++ {
				if data[i] == '\\' {
					i++
					continue
				}
				if data[i] == '"' {
					break
				}
			}
			root(start, min(i, len(data)))
		}
	case "text/css":
		css(0, len(data))
	default:
		for i := 0; i < len(data); {
			if data[i] != '<' {
				i++
				continue
			}
			if bytes.HasPrefix(data[i:], []byte("<!--")) {
				end := bytes.Index(data[i+4:], []byte("-->"))
				if end < 0 {
					break
				}
				i += 4 + end + 3
				continue
			}
			i++
			start := i
			for i < len(data) && !space(data[i]) && data[i] != '>' && data[i] != '/' {
				i++
			}
			tag := strings.ToLower(string(data[start:i]))
			for i < len(data) && data[i] != '>' {
				if space(data[i]) || data[i] == '/' {
					i++
					continue
				}
				start = i
				for i < len(data) && !space(data[i]) && data[i] != '=' && data[i] != '>' {
					i++
				}
				name := strings.ToLower(string(data[start:i]))
				for i < len(data) && space(data[i]) {
					i++
				}
				if i == len(data) || data[i] != '=' {
					continue
				}
				i++
				for i < len(data) && space(data[i]) {
					i++
				}
				if i == len(data) {
					break
				}
				quote := byte(0)
				if data[i] == '\'' || data[i] == '"' {
					quote = data[i]
					i++
				}
				start = i
				for i < len(data) && (quote != 0 && data[i] != quote || quote == 0 && !space(data[i]) && data[i] != '>') {
					i++
				}
				end := i
				switch name {
				case "href", "src", "action", "formaction", "poster", "data", "manifest", "background", "xlink:href":
					root(start, end)
				case "srcset":
					for j := start; j < end; {
						for j < end && (space(data[j]) || data[j] == ',') {
							j++
						}
						k := j
						for k < end && !space(data[k]) && data[k] != ',' {
							k++
						}
						root(j, k)
						for k < end && data[k] != ',' {
							k++
						}
						j = k
					}
				case "style":
					css(start, end)
				}
				if quote != 0 && i < len(data) {
					i++
				}
			}
			if i < len(data) {
				i++
			}
			if tag == "script" || tag == "style" || tag == "textarea" || tag == "title" {
				end := i
				for end < len(data) {
					if data[end] == '<' && end+2+len(tag) <= len(data) && data[end+1] == '/' && strings.EqualFold(string(data[end+2:end+2+len(tag)]), tag) {
						break
					}
					end++
				}
				if tag == "style" {
					css(i, end)
				}
				i = end
			}
		}
	}
	if out == nil {
		return data
	}
	if overflow || len(out)+len(data)-last > 2*sudokuReverseBodyLimit {
		return data
	}
	return append(out, data[last:]...)
}
