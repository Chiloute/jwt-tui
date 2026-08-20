package style

import (
	"strings"

	"charm.land/lipgloss/v2"
	ilovetui "github.com/anotherhadi/ilovetui"
)

func PanelBorder(focused bool) lipgloss.Style {
	base := ilovetui.S.Panel
	if focused {
		base = ilovetui.S.PanelFocused
	}
	return base.Padding(0, 1)
}

func PanelContentSize(border lipgloss.Style, width, height int) (int, int) {
	if width < 3 {
		width = 3
	}
	if height < 2 {
		height = 2
	}
	// lipgloss's Width()/Height() already set the box's total size including
	// its border, so content width is just the horizontal frame (border +
	// padding) subtracted once. Height loses 1 row to the title (rendered
	// separately, outside the border box) and 1 to the bottom border (the
	// only border row drawn, since BorderTop is off in RenderWithTitle).
	w := width - border.GetHorizontalFrameSize()
	h := height - 2 - border.GetVerticalPadding()
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	return w, h
}

func RenderWithTitle(border lipgloss.Style, title, content string, width, height int) string {
	if width < 3 {
		width = 3
	}
	if height < 2 {
		height = 2
	}

	// lipgloss's Width()/Height() set the box's total rendered size,
	// borders included, so boxW is just width. boxH only drops 1 row for
	// the title line drawn separately below; Height() itself accounts for
	// the box's own bottom border row (its only remaining border, since
	// BorderTop is disabled).
	boxW := width
	boxH := height - 1
	if boxH < 1 {
		boxH = 1
	}

	box := border.BorderTop(false).Width(boxW).Height(boxH).Render(content)

	// lipgloss's Height() is a minimum, not a maximum: content taller than
	// boxH (e.g. placeholder text rendered outside a viewport, which would
	// normally clip itself) is not truncated and grows the box past its
	// allocation. Clip to boxH here, keeping the bottom border row intact.
	if boxLines := strings.Split(box, "\n"); len(boxLines) > boxH {
		boxLines = append(boxLines[:boxH-1], boxLines[len(boxLines)-1])
		box = strings.Join(boxLines, "\n")
	}

	bodyW := lipgloss.Width(strings.SplitN(box, "\n", 2)[0])
	// "╭ " + title + " " + fill + "╮" must never exceed bodyW, or the top
	// border overflows into the neighboring panel and breaks grid alignment.
	availTitleW := bodyW - 4
	if availTitleW < 0 {
		availTitleW = 0
	}
	if lipgloss.Width(title) > availTitleW {
		title = lipgloss.NewStyle().MaxWidth(availTitleW).Render(title)
	}
	titleW := lipgloss.Width(title)
	fillW := bodyW - titleW - 4
	if fillW < 0 {
		fillW = 0
	}
	bc := lipgloss.NewStyle().Foreground(border.GetBorderTopForeground())
	topLine := bc.Render("╭ ") + title + bc.Render(" "+strings.Repeat("─", fillW)+"╮")

	return lipgloss.JoinVertical(lipgloss.Left, topLine, box)
}
