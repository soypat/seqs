package httpx

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type header struct {
	statusCode           int
	contentLength        int
	host                 []byte
	contentLengthBytes   []byte
	contentType          []byte
	userAgent            []byte
	method               []byte
	proto                []byte
	requestURI           []byte
	rawHeaders           []byte
	mulHeader            []byte
	cookies              []argsKV
	disableNormalizing   bool
	disableSpecialHeader bool
	connectionClose      bool
	noHTTP11             bool
	cookiesCollected     bool
	// Reusable buffer for building strings.
	bufKV   argsKV
	h       []argsKV
	trailer []argsKV
}

func (h *header) SetContentRange(startPos, endPos, contentLength int) {
	b := h.bufKV.value[:0]
	b = append(b, strBytes...)
	b = append(b, ' ')
	b = AppendUint(b, startPos)
	b = append(b, '-')
	b = AppendUint(b, endPos)
	b = append(b, '/')
	b = AppendUint(b, contentLength)
	h.bufKV.value = b

	h.setNonSpecial(strContentRange, b2s(h.bufKV.value))
}

// setNonSpecial directly put into map i.e. not a basic header.
func (h *header) setNonSpecial(key string, value string) {
	h.h = setArg(h.h, key, value, argsHasValue)
}

// StatusCode returns response status code.
func (h *header) StatusCode() int {
	if h.statusCode == 0 {
		return http.StatusOK
	}
	return h.statusCode
}

func AppendUint(b []byte, v int) []byte {
	if v < 0 {
		panic("negative uint")
	}
	return strconv.AppendUint(b, uint64(v), 10)
}

// ContentLength returns Content-Length header value.
//
// It may be negative:
// -1 means Transfer-Encoding: chunked.
// -2 means Transfer-Encoding: identity.
func (h *header) ContentLength() int {
	return h.contentLength
}

// SetContentLength sets Content-Length header value.
//
// Content-Length may be negative:
// -1 means Transfer-Encoding: chunked.
// -2 means Transfer-Encoding: identity.
func (h *header) SetContentLength(contentLength int) {
	h.contentLength = contentLength
	if contentLength >= 0 {
		h.contentLengthBytes = AppendUint(h.contentLengthBytes[:0], contentLength)
		h.h = delAllArgs(h.h, strTransferEncoding)
	} else {
		h.contentLengthBytes = h.contentLengthBytes[:0]
		h.h = setArg(h.h, strTransferEncoding, strChunked, argsHasValue)
	}
}

var ErrBadTrailer = errors.New("contain forbidden trailer")

// SetTrailer sets Trailer header value for chunked request
// to indicate which headers will be sent after the body.
//
// Use Set to set the trailer header later.
//
// Trailers are only supported with chunked transfer.
// Trailers allow the sender to include additional headers at the end of chunked messages.
//
// The following trailers are forbidden:
// 1. necessary for message framing (e.g., Transfer-Encoding and Content-Length),
// 2. routing (e.g., Host),
// 3. request modifiers (e.g., controls and conditionals in Section 5 of [RFC7231]),
// 4. authentication (e.g., see [RFC7235] and [RFC6265]),
// 5. response control data (e.g., see Section 7.1 of [RFC7231]),
// 6. determining how to process the payload (e.g., Content-Encoding, Content-Type, Content-Range, and Trailer)
//
// Return ErrBadTrailer if contain any forbidden trailers.
func (h *header) SetTrailer(trailer string) error {
	h.trailer = h.trailer[:0]
	return h.AddTrailer(trailer)
}

// AddTrailerBytes add Trailer header value for chunked response
// to indicate which headers will be sent after the body.
//
// Use Set to set the trailer header later.
//
// Trailers are only supported with chunked transfer.
// Trailers allow the sender to include additional headers at the end of chunked messages.
//
// The following trailers are forbidden:
// 1. necessary for message framing (e.g., Transfer-Encoding and Content-Length),
// 2. routing (e.g., Host),
// 3. request modifiers (e.g., controls and conditionals in Section 5 of [RFC7231]),
// 4. authentication (e.g., see [RFC7235] and [RFC6265]),
// 5. response control data (e.g., see Section 7.1 of [RFC7231]),
// 6. determining how to process the payload (e.g., Content-Encoding, Content-Type, Content-Range, and Trailer)
//
// Return ErrBadTrailer if contain any forbidden trailers.
func (h *header) AddTrailer(trailer string) error {
	var err error
	for i := -1; i+1 < len(trailer); {
		trailer = trailer[i+1:]
		i = strings.IndexByte(trailer, ',')
		if i < 0 {
			i = len(trailer)
		}
		key := stripSpace(trailer[:i])
		// Forbidden by RFC 7230, section 4.1.2
		if isBadTrailer(key) {
			err = ErrBadTrailer
			continue
		}
		h.bufKV.key = append(h.bufKV.key[:0], key...)
		normalizeHeaderKey(h.bufKV.key, h.disableNormalizing)
		h.trailer = appendArg(h.trailer, b2s(h.bufKV.key), "", argsNoValue)
	}

	return err
}

func isBadTrailer(key string) bool {
	if len(key) == 0 {
		return true
	}

	switch key[0] | 0x20 {
	case 'a':
		return caseInsensitiveCompare(key, strAuthorization)
	case 'c':
		if len(key) > len(HeaderContentType) && caseInsensitiveCompare(key[:8], strContentType[:8]) {
			// skip compare prefix 'Content-'
			return caseInsensitiveCompare(key[8:], strContentEncoding[8:]) ||
				caseInsensitiveCompare(key[8:], strContentLength[8:]) ||
				caseInsensitiveCompare(key[8:], strContentType[8:]) ||
				caseInsensitiveCompare(key[8:], strContentRange[8:])
		}
		return caseInsensitiveCompare(key, strConnection)
	case 'e':
		return caseInsensitiveCompare(key, strExpect)
	case 'h':
		return caseInsensitiveCompare(key, strHost)
	case 'k':
		return caseInsensitiveCompare(key, strKeepAlive)
	case 'm':
		return caseInsensitiveCompare(key, strMaxForwards)
	case 'p':
		if len(key) > len(HeaderProxyConnection) && caseInsensitiveCompare(key[:6], strProxyConnection[:6]) {
			// skip compare prefix 'Proxy-'
			return caseInsensitiveCompare(key[6:], strProxyConnection[6:]) ||
				caseInsensitiveCompare(key[6:], strProxyAuthenticate[6:]) ||
				caseInsensitiveCompare(key[6:], strProxyAuthorization[6:])
		}
	case 'r':
		return caseInsensitiveCompare(key, strRange)
	case 't':
		return caseInsensitiveCompare(key, strTE) ||
			caseInsensitiveCompare(key, strTrailer) ||
			caseInsensitiveCompare(key, strTransferEncoding)
	case 'w':
		return caseInsensitiveCompare(key, strWWWAuthenticate)
	}
	return false
}
