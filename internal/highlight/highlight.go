package highlight

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	ilovetui "github.com/anotherhadi/ilovetui"
)

func paint(c color.Color, s string) string {
	return lipgloss.NewStyle().Foreground(c).Render(s)
}

func JSON(s string) string {
	var out strings.Builder
	i, n := 0, len(s)
	for i < n {
		ch := s[i]
		switch {
		case ch == '"':
			j := i + 1
			for j < n {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == '"' {
					j++
					break
				}
				j++
			}
			str := s[i:j]
			k := j
			for k < n && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			if k < n && s[k] == ':' {
				out.WriteString(paint(ilovetui.S.Primary, str))
			} else {
				out.WriteString(paint(ilovetui.S.Success, str))
			}
			i = j
		case (ch >= '0' && ch <= '9') || (ch == '-' && i+1 < n && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i
			if s[j] == '-' {
				j++
			}
			for j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.' || s[j] == 'e' || s[j] == 'E' || s[j] == '+' || s[j] == '-') {
				j++
			}
			out.WriteString(paint(ilovetui.S.Warning, s[i:j]))
			i = j
		case i+4 <= n && s[i:i+4] == "true":
			out.WriteString(paint(ilovetui.S.Error, "true"))
			i += 4
		case i+5 <= n && s[i:i+5] == "false":
			out.WriteString(paint(ilovetui.S.Error, "false"))
			i += 5
		case i+4 <= n && s[i:i+4] == "null":
			out.WriteString(paint(ilovetui.S.Muted, "null"))
			i += 4
		case ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == ':' || ch == ',':
			out.WriteString(paint(ilovetui.S.Subtle, string(ch)))
			i++
		default:
			out.WriteByte(ch)
			i++
		}
	}
	return out.String()
}

func JWT(s string) string {
	dot := paint(ilovetui.S.Subtle, ".")
	parts := strings.SplitN(s, ".", 3)
	switch len(parts) {
	case 1:
		return paint(ilovetui.S.Primary, parts[0])
	case 2:
		return paint(ilovetui.S.Primary, parts[0]) + dot + paint(ilovetui.S.Success, parts[1])
	default:
		return paint(ilovetui.S.Primary, parts[0]) + dot +
			paint(ilovetui.S.Success, parts[1]) + dot +
			paint(ilovetui.S.Warning, parts[2])
	}
}
