package version

import "fmt"

// KernelVersion represents a minimum kernel version as major.minor.
type KernelVersion struct {
	Major int
	Minor int
}

// V is a convenience constructor.
func V(major, minor int) KernelVersion {
	return KernelVersion{Major: major, Minor: minor}
}

func (v KernelVersion) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Less returns true if v is strictly less than other.
func (v KernelVersion) Less(other KernelVersion) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	return v.Minor < other.Minor
}

// MarshalJSON implements json.Marshaler, serializing as "5.8".
func (v KernelVersion) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, v.String())), nil
}
