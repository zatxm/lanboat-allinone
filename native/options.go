package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// sing-box permits a scalar in place of a one-element list throughout options.
func decodeOptions(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if e := d.Decode(&value); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("extra JSON data")
	}
	value = normalizeOptionLists(value, reflect.TypeOf(out).Elem())
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func normalizeOptionLists(v any, t reflect.Type) any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if v == nil {
		return v
	}
	switch t.Kind() {
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return v
		}
		items, ok := v.([]any)
		if !ok {
			items = []any{v}
		}
		for i, item := range items {
			items[i] = normalizeOptionLists(item, t.Elem())
		}
		return items
	case reflect.Map:
		if m, ok := v.(map[string]any); ok {
			for k, item := range m {
				m[k] = normalizeOptionLists(item, t.Elem())
			}
		}
		return v
	case reflect.Struct:
		if m, ok := v.(map[string]any); ok {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() {
					continue
				}
				if f.Anonymous {
					normalizeOptionLists(m, f.Type)
					continue
				}
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "-" {
					continue
				}
				if name == "" {
					name = f.Name
				}
				if item, exists := m[name]; exists {
					if name == "version" && f.Type.Kind() == reflect.String {
						if n, ok := item.(json.Number); ok {
							m[name] = n.String()
							continue
						}
					}
					m[name] = normalizeOptionLists(item, f.Type)
				}
			}
		}
		return v
	}
	return v
}
func optionDuration(value string, defaultValue time.Duration) (time.Duration, error) {
	if value == "" {
		return defaultValue, nil
	}
	if strings.HasSuffix(value, "d") {
		n, e := strconv.ParseFloat(strings.TrimSuffix(value, "d"), 64)
		if e != nil || math.IsNaN(n) || n <= 0 || n > 3650 {
			return 0, errors.New("invalid day duration")
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	d, e := time.ParseDuration(value)
	if e != nil || d <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return d, nil
}
