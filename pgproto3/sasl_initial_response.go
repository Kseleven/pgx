package pgproto3

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/Kseleven/pgx/v5/internal/pgio"
)

type SASLInitialResponse struct {
	AuthMechanism string
	Data          []byte
	IsECDHESHA256 bool
}

// Frontend identifies this message as sendable by a PostgreSQL frontend.
func (*SASLInitialResponse) Frontend() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *SASLInitialResponse) Decode(src []byte) error {
	*dst = SASLInitialResponse{}

	rp := 0

	idx := bytes.IndexByte(src, 0)
	if idx < 0 {
		return errors.New("invalid SASLInitialResponse")
	}

	dst.AuthMechanism = string(src[rp:idx])
	rp = idx + 1

	rp += 4 // The rest of the message is data so we can just skip the size
	dst.Data = src[rp:]

	return nil
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *SASLInitialResponse) Encode(dst []byte) ([]byte, error) {
	if src.IsECDHESHA256 {
		dst = append(dst, src.encodeECDHESHA256()...)
		return finishMessage(dst, 1)
	}

	dst, sp := beginMessage(dst, 'p')
	dst = append(dst, []byte(src.AuthMechanism)...)
	dst = append(dst, 0)
	dst = pgio.AppendInt32(dst, int32(len(src.Data)))
	dst = append(dst, src.Data...)
	return finishMessage(dst, sp)

}

func (src *SASLInitialResponse) encodeECDHESHA256() []byte {
	var buf bytes.Buffer
	buf.Write([]byte("p"))
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(4+len(src.Data)+1))
	buf.Write(x)
	buf.Write(src.Data)
	buf.Write([]byte{0})

	return buf.Bytes()
}

// MarshalJSON implements encoding/json.Marshaler.
func (src SASLInitialResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type          string
		AuthMechanism string
		Data          string
	}{
		Type:          "SASLInitialResponse",
		AuthMechanism: src.AuthMechanism,
		Data:          string(src.Data),
	})
}

// UnmarshalJSON implements encoding/json.Unmarshaler.
func (dst *SASLInitialResponse) UnmarshalJSON(data []byte) error {
	// Ignore null, like in the main JSON package.
	if string(data) == "null" {
		return nil
	}

	var msg struct {
		AuthMechanism string
		Data          string
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}
	dst.AuthMechanism = msg.AuthMechanism
	if msg.Data != "" {
		decoded, err := hex.DecodeString(msg.Data)
		if err != nil {
			return err
		}
		dst.Data = decoded
	}
	return nil
}
