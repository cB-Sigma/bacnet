package bacnet

import (
	"encoding/binary"
	"net"
	"strconv"
)

func Be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

const (
	DefaultPort = 47808
)

func WithPort(a string) string {
	if _, _, err := net.SplitHostPort(a); err != nil {
		return net.JoinHostPort(a, strconv.Itoa(DefaultPort))
	}
	return a
}
