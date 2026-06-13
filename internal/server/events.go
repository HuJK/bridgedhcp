package server

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Events are single-line JSON objects on stdout, consumed by a supervising
// daemon (DroidVM pumps child stdout line-wise). Logs go to stderr, so
// stdout stays machine-readable.
var eventMu sync.Mutex

// Emit writes one event line: {"event":type, "ts":..., fields...}.
func Emit(typ string, fields map[string]any) {
	obj := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		obj[k] = v
	}
	obj["event"] = typ
	obj["ts"] = time.Now().Unix()
	line, err := json.Marshal(obj)
	if err != nil {
		return
	}
	eventMu.Lock()
	defer eventMu.Unlock()
	os.Stdout.Write(append(line, '\n'))
}
