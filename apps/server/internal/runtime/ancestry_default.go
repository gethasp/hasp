//go:build !unix

package runtime

func processLineage(pid int) ([]int, error) {
	if pid <= 0 {
		return nil, nil
	}
	return []int{pid}, nil
}
