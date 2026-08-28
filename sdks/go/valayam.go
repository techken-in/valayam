package valayam

import (
	"encoding/json"
	"errors"
)

// PluginCaps represents capabilities a plugin requires
type PluginCaps []string

// Host exports methods for WASM plugins to communicate with Valayam Engine
type Host interface {
	GetKV(key string) (string, error)
	SetKV(key, value string) error
	ResolveDNS(domain string) ([]string, error)
}

// Result is a normalized finding result
type Result struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SDK struct simplifies interactions
type SDK struct {
	host Host
}

// NewSDK initializes a new SDK instance with host callbacks
func NewSDK(h Host) *SDK {
	return &SDK{host: h}
}

func (s *SDK) ReportFinding(res Result) error {
	// serialize and send out of band or via host function
	_, err := json.Marshal(res)
	if err != nil {
		return err
	}
	// TODO: communicate with host
	return errors.New("not implemented")
}
