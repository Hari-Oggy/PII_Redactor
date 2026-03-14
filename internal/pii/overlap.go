package pii

import (
	"sync"
)

// OverlapBuffer maintains a sliding window of bytes across streaming
// chunks to ensure PII patterns that span chunk boundaries are detected.
// The buffer retains the last N bytes from the previous chunk and
// prepends them to the current chunk for scanning.
type OverlapBuffer struct {
	mu       sync.Mutex
	size     int    // how many bytes to retain
	buffer   []byte // retained bytes from previous chunk
}

// NewOverlapBuffer creates an overlap buffer with the given size.
func NewOverlapBuffer(size int) *OverlapBuffer {
	if size <= 0 {
		size = 128 // default
	}
	return &OverlapBuffer{
		size:   size,
		buffer: make([]byte, 0, size),
	}
}

// Process takes a new chunk and returns a scan window that includes
// the overlap from the previous chunk. It also updates the buffer
// with the last N bytes of the current chunk for the next call.
//
// Returns:
//   - scanWindow: the full text to scan (overlap + current chunk)
//   - overlapLen: how many bytes of the scan window are from the overlap
//     (callers should only emit bytes after scanWindow[overlapLen:])
func (ob *OverlapBuffer) Process(chunk []byte) (scanWindow []byte, overlapLen int) {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	// Build scan window: previous overlap + current chunk.
	overlapLen = len(ob.buffer)
	scanWindow = make([]byte, overlapLen+len(chunk))
	copy(scanWindow, ob.buffer)
	copy(scanWindow[overlapLen:], chunk)

	// Update buffer with the last N bytes of the current chunk.
	if len(chunk) >= ob.size {
		ob.buffer = make([]byte, ob.size)
		copy(ob.buffer, chunk[len(chunk)-ob.size:])
	} else {
		// Chunk is smaller than buffer size — combine with existing overlap.
		combined := append(ob.buffer, chunk...)
		if len(combined) > ob.size {
			ob.buffer = combined[len(combined)-ob.size:]
		} else {
			ob.buffer = combined
		}
	}

	return scanWindow, overlapLen
}

// Flush returns any remaining bytes in the buffer and resets it.
func (ob *OverlapBuffer) Flush() []byte {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	remaining := ob.buffer
	ob.buffer = make([]byte, 0, ob.size)
	return remaining
}
