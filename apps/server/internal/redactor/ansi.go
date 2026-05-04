package redactor

// stripANSI scans buf and returns a "visible" view with ANSI escape sequences
// removed, an index map (visible[i] originated at buf[indexMap[i]]) and the
// count of trailing bytes that are part of an in-progress escape sequence —
// those bytes were NOT visited and must be retained for the next round so
// matching never sees a half-decoded sequence.
//
// Recognised forms (covers >99% of terminal output in practice):
//
//   - CSI: ESC '[' (params)* (final 0x40-0x7e)
//   - OSC: ESC ']' ... terminator (BEL or ESC '\\')
//   - Two-char escapes: ESC (final 0x40-0x5f) when neither '[' nor ']'
//
// Anything we do not recognise (a bare 0x1b at end-of-buffer, or an OSC
// without a terminator yet) is reported as in-progress so the caller will
// retain it. We never emit a partial escape into the visible view.
func stripANSI(buf []byte) (visible []byte, indexMap []int, inProgress int) {
	visible = make([]byte, 0, len(buf))
	indexMap = make([]int, 0, len(buf))
	i := 0
	for i < len(buf) {
		if buf[i] != 0x1b {
			visible = append(visible, buf[i])
			indexMap = append(indexMap, i)
			i++
			continue
		}
		end, ok := scanEscape(buf, i)
		if !ok {
			inProgress = len(buf) - i
			return
		}
		i = end
	}
	return
}

// scanEscape returns the index just past the end of a complete ANSI escape
// sequence starting at buf[start]. ok=false means the sequence is in-progress
// (truncated by buffer end) and the caller must retain the trailing bytes.
//
// Precondition: buf[start] == 0x1b.
func scanEscape(buf []byte, start int) (int, bool) {
	if start+1 >= len(buf) {
		return 0, false
	}
	switch buf[start+1] {
	case '[':
		j := start + 2
		for j < len(buf) {
			c := buf[j]
			if c >= 0x40 && c <= 0x7e {
				return j + 1, true
			}
			j++
		}
		return 0, false
	case ']':
		j := start + 2
		for j < len(buf) {
			c := buf[j]
			if c == 0x07 {
				return j + 1, true
			}
			if c == 0x1b {
				if j+1 < len(buf) && buf[j+1] == '\\' {
					return j + 2, true
				}
				return 0, false
			}
			j++
		}
		return 0, false
	default:
		c := buf[start+1]
		if c >= 0x40 && c <= 0x5f {
			return start + 2, true
		}
		// Unknown second byte; treat the lone ESC as a single skipped byte
		// so we don't deadlock on garbage. Caller's loop advances past it.
		return start + 1, true
	}
}
