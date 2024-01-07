package httpx

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"time"
)

type ResponseHeader struct {
	statusCode    int
	server        []byte
	statusMessage []byte
	now           time.Time
	hdr           header
}

func (h *ResponseHeader) serverTime() time.Time {
	if !h.now.IsZero() {
		return h.now
	}
	return time.Now()
}

// Reset clears response header. It is ready for new use after returning from Reset.
func (h *ResponseHeader) Reset() {
	h.hdr.disableNormalizing = false
	// h.SetNoDefaultContentType(false)
	// h.noDefaultDate = false
	h.server = h.server[:0]
	h.statusMessage = h.statusMessage[:0]
	h.statusCode = 0
	h.hdr.resetSkipNormalize()
}

// SetContentType sets Content-Type header value. i.e: "text/html; charset=utf-8"
func (h *ResponseHeader) SetContentType(contentType string) {
	h.hdr.SetContentType(contentType)
}

// SetContentLength sets Content-Length header value.
func (h *ResponseHeader) SetContentLength(contentLength int) {
	h.hdr.SetContentLength(contentLength)
}

// Server returns Server header value.
func (h *ResponseHeader) Server() []byte { return h.server }

// SetServer sets Server header value.
func (h *ResponseHeader) SetServer(server string) {
	h.server = append(h.server[:0], server...)
}

// StatusCode returns response status code.
func (h *ResponseHeader) StatusCode() int {
	if h.statusCode == 0 {
		return http.StatusOK
	}
	return h.statusCode
}

// StatusMessage returns response status message.
func (h *ResponseHeader) StatusMessage() []byte {
	return h.statusMessage
}

// Write writes response header to w.
func (h *ResponseHeader) Write(w *bufio.Writer) error {
	_, err := w.Write(h.Header())
	return err
}

// WriteTo writes response header to w.
//
// WriteTo implements io.WriterTo interface.
func (h *ResponseHeader) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h.Header())
	return int64(n), err
}

// Header returns response header representation.
//
// Headers that set as Trailer will not represent. Use TrailerHeader for trailers.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *ResponseHeader) Header() []byte {
	h.hdr.bufKV.value = h.AppendBytes(h.hdr.bufKV.value[:0])
	return h.hdr.bufKV.value
}

// SetStatusCode sets response status code. If not set will default to 200 (Status OK).
func (h *ResponseHeader) SetStatusCode(statusCode int) {
	h.statusCode = statusCode
}

// SetConnectionClose sets 'Connection: close' header.
func (h *ResponseHeader) SetConnectionClose() {
	h.hdr.SetConnectionClose()
}

// Add adds the given 'key: value' header.
//
// Multiple headers with the same key may be added with this function.
// Use SetBytesKV for setting a single header for the given key.
//
// the Content-Type, Content-Length, Connection, Server, Set-Cookie,
// Transfer-Encoding and Date headers can only be set once and will
// overwrite the previous value.
//
// If the header is set as a Trailer (forbidden trailers will not be set, see AddTrailer for more details),
// it will be sent after the chunked response body.
func (h *ResponseHeader) Add(key, value string) {
	h.hdr.Add(key, value)
}

// Peek returns header value for the given key.
//
// The returned value is valid until the response is released,
// either though ReleaseResponse or your request handler returning.
// Do not store references to the returned value. Make copies instead.
func (h *ResponseHeader) Peek(key string) []byte {
	return h.hdr.Peek(key)
}

// AppendBytes appends response header representation to dst and returns
// the extended dst.
func (h *ResponseHeader) AppendBytes(dst []byte) []byte {
	h.hdr.trace("httpx:RspHdr.AppendBytes")
	dst = h.appendStatusLine(dst[:0])

	server := h.Server()
	if len(server) != 0 {
		dst = appendHeaderLine(dst, strServer, b2s(server))
	}

	// if !h.noDefaultDate {
	// now := h.serverTime()
	// now.AppendFormat()
	// serverDateOnce.Do(updateServerDate)
	// dst = appendHeaderLine(dst, strDate, serverDate.Load().([]byte))
	// }

	// Append Content-Type only for non-zero responses
	// or if it is explicitly set.
	// See https://github.com/valyala/fasthttp/issues/28 .
	if h.hdr.ContentLength() != 0 || len(h.hdr.contentType) > 0 {
		contentType := h.hdr.ContentType()
		if len(contentType) > 0 {
			dst = appendHeaderLine(dst, strContentType, b2s(contentType))
		}
	}
	contentEncoding := h.hdr.ContentEncoding()
	if len(contentEncoding) > 0 {
		dst = appendHeaderLine(dst, strContentEncoding, b2s(contentEncoding))
	}

	if len(h.hdr.contentLengthBytes) > 0 {
		dst = appendHeaderLine(dst, strContentLength, b2s(h.hdr.contentLengthBytes))
	}

	return h.hdr.AppendReqRespCommon(dst)
}

// appendStatusLine appends the response status line to dst and returns
// the extended dst.
func (h *ResponseHeader) appendStatusLine(dst []byte) []byte {
	statusCode := h.StatusCode()
	if statusCode < 0 {
		statusCode = 200
	}
	return formatStatusLine(dst, h.hdr.Protocol(), statusCode, h.StatusMessage())
}

func formatStatusLine(dst []byte, protocol []byte, statusCode int, statusText []byte) []byte {
	dst = append(dst, protocol...)
	dst = append(dst, ' ')
	dst = strconv.AppendInt(dst, int64(statusCode), 10)
	dst = append(dst, ' ')
	if len(statusText) == 0 {
		dst = append(dst, StatusMessage(statusCode)...)
	} else {
		dst = append(dst, statusText...)
	}
	return append(dst, strCRLF...)
}

// StatusMessage returns HTTP status message for the given status code.
func StatusMessage(statusCode int) string {
	const (
		statusMessageMin  = 100
		statusMessageMax  = 511
		unknownStatusCode = "Unknown Status Code"
	)
	if statusCode < statusMessageMin || statusCode > statusMessageMax {
		return unknownStatusCode
	}

	if s := http.StatusText(statusCode); s != "" {
		return s
	}
	return unknownStatusCode
}
