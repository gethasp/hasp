//go:build unix

package runtime

var processParentPID = realProcessParentPID

func processLineage(pid int) ([]int, error) {
	if pid <= 0 {
		return nil, nil
	}
	seen := map[int]struct{}{}
	lineage := make([]int, 0, 8)
	current := pid
	for current > 0 {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		lineage = append(lineage, current)
		parent, err := processParentPID(current)
		if err != nil {
			return lineage, nil
		}
		if parent <= 1 || parent == current {
			break
		}
		current = parent
	}
	return lineage, nil
}
