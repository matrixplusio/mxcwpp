package bde

import (
	"fmt"
	"strconv"
)

func formatInt(v int) string       { return strconv.Itoa(v) }
func formatInt64(v int64) string   { return strconv.FormatInt(v, 10) }
func formatFloat(v float64) string { return fmt.Sprintf("%.4f", v) }
