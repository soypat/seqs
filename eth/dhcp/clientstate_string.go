// Code generated by "stringer -type=ClientState -trimprefix=State"; DO NOT EDIT.

package dhcp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StateInit-1]
	_ = x[StateSelecting-2]
	_ = x[StateRequesting-3]
	_ = x[StateBound-4]
}

const _ClientState_name = "InitSelectingRequestingBound"

var _ClientState_index = [...]uint8{0, 4, 13, 23, 28}

func (i ClientState) String() string {
	i -= 1
	if i >= ClientState(len(_ClientState_index)-1) {
		return "ClientState(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ClientState_name[_ClientState_index[i]:_ClientState_index[i+1]]
}
