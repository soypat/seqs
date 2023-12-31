package httpx

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type ResponseHeader struct {
	hdr header
}

type RequestHeader struct {
	header
}

type header struct {
	statusCode         int
	contentLength      int
	host               []byte
	contentLengthBytes []byte
	contentType        []byte
	userAgent          []byte
	method             []byte
	proto              []byte
	requestURI         []byte
	rawHeaders         []byte
	mulHeader          []byte

	disableNormalizing   bool
	disableSpecialHeader bool
	noDefaultContentType bool
	connectionClose      bool
	noHTTP11             bool
	cookiesCollected     bool
	// Reusable buffer for building strings.
	bufKV   argsKV
	h       []argsKV
	cookies []argsKV
	trailer []argsKV
	scanner headerScanner
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

// RawHeaders returns raw header key/value bytes.
//
// Depending on server configuration, header keys may be normalized to
// capital-case in place.
//
// This copy is set aside during parsing, so empty slice is returned for all
// cases where parsing did not happen. Similarly, request line is not stored
// during parsing and can not be returned.
//
// The slice is not safe to use after the handler returns.
func (h *header) RawHeaders() []byte {
	return h.rawHeaders
}

// DisableNormalizing disables header names' normalization.
//
// By default all the header names are normalized by uppercasing
// the first letter and all the first letters following dashes,
// while lowercasing all the other letters.
// Examples:
//
//   - CONNECTION -> Connection
//   - conteNT-tYPE -> Content-Type
//   - foo-bar-baz -> Foo-Bar-Baz
//
// Disable header names' normalization only if know what are you doing.
func (h *header) DisableNormalizing() {
	h.disableNormalizing = true
}

// DisableSpecialHeader disables special header processing.
// fasthttp will not set any special headers for you, such as Host, Content-Type, User-Agent, etc.
// You must set everything yourself.
// If RequestHeader.Read() is called, special headers will be ignored.
// This can be used to control case and order of special headers.
// This is generally not recommended.
func (h *header) DisableSpecialHeader() {
	h.disableSpecialHeader = true
}

// String returns request header representation.
func (h *header) String() string {
	return string(h.Header())
}

// Header returns request header representation.
//
// Headers that set as Trailer will not represent. Use TrailerHeader for trailers.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *header) Header() []byte {
	h.bufKV.value = h.AppendBytes(h.bufKV.value[:0])
	return h.bufKV.value
}

// Method returns HTTP request method.
func (h *header) Method() []byte {
	if len(h.method) == 0 {
		h.method = append(h.method, http.MethodGet...)
	}
	return h.method
}

// RequestURI returns RequestURI from the first HTTP request line.
func (h *header) RequestURI() []byte {
	requestURI := h.requestURI
	if len(requestURI) == 0 {
		requestURI = append(requestURI, '/')
	}
	return requestURI
}

// Protocol returns HTTP protocol.
func (h *header) Protocol() []byte {
	if len(h.proto) == 0 {
		h.proto = append(h.proto, strHTTP11...)
	}
	return h.proto
}

// AppendBytes appends request header representation to dst and returns
// the extended dst.
func (h *header) AppendBytes(dst []byte) []byte {
	dst = append(dst, h.Method()...)
	dst = append(dst, ' ')
	dst = append(dst, h.RequestURI()...)
	dst = append(dst, ' ')
	dst = append(dst, h.Protocol()...)
	dst = append(dst, strCRLF...)

	userAgent := h.UserAgent()
	if len(userAgent) > 0 && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strUserAgent, b2s(userAgent))
	}

	host := h.Host()
	if len(host) > 0 && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strHost, b2s(host))
	}

	contentType := h.ContentType()
	if !h.noDefaultContentType && len(contentType) == 0 && !h.ignoreBody() {
		contentType = append(contentType, strDefaultContentType...)
	}
	if len(contentType) > 0 && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strContentType, b2s(contentType))
	}
	if len(h.contentLengthBytes) > 0 && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strContentLength, b2s(h.contentLengthBytes))
	}

	for i, n := 0, len(h.h); i < n; i++ {
		kv := &h.h[i]
		// Exclude trailer from header
		exclude := false
		for _, t := range h.trailer {
			if bytes.Equal(kv.key, t.key) {
				exclude = true
				break
			}
		}
		if !exclude {
			dst = appendHeaderLine(dst, b2s(kv.key), b2s(kv.value))
		}
	}

	if len(h.trailer) > 0 {
		aux := appendArgsKey(nil, h.trailer, strCommaSpace)
		dst = appendHeaderLine(dst, strTrailer, b2s(aux))
	}

	// there is no need in h.collectCookies() here, since if cookies aren't collected yet,
	// they all are located in h.h.
	n := len(h.cookies)
	if n > 0 && !h.disableSpecialHeader {
		dst = append(dst, strCookie...)
		dst = append(dst, strColonSpace...)
		dst = appendRequestCookieBytes(dst, h.cookies)
		dst = append(dst, strCRLF...)
	}

	if h.ConnectionClose() && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strConnection, strClose)
	}

	return append(dst, strCRLF...)
}

func appendHeaderLine(dst []byte, key, value string) []byte {
	dst = append(dst, key...)
	dst = append(dst, strColonSpace...)
	dst = append(dst, value...)
	return append(dst, strCRLF...)
}

func (h *header) ignoreBody() bool {
	return h.IsGet() || h.IsHead()
}

func (h *header) MethodIs(method string) bool {
	return b2s(h.method) == method
}

// IsGet returns true if request method is GET.
func (h *header) IsGet() bool { return len(h.method) == 0 || h.MethodIs(http.MethodGet) }

// IsHead returns true if request method is HEAD.
func (h *header) IsHead() bool { return h.MethodIs(http.MethodHead) }

// IsPost returns true if request method is POST.
func (h *header) IsPost() bool { return h.MethodIs(http.MethodPost) }

// IsPut returns true if request method is PUT.
func (h *header) IsPut() bool { return h.MethodIs(http.MethodPut) }

// IsDelete returns true if request method is DELETE.
func (h *header) IsDelete() bool { return h.MethodIs(http.MethodDelete) }

// IsConnect returns true if request method is CONNECT.
func (h *header) IsConnect() bool { return h.MethodIs(http.MethodConnect) }

// IsOptions returns true if request method is OPTIONS.
func (h *header) IsOptions() bool { return h.MethodIs(http.MethodOptions) }

// IsTrace returns true if request method is TRACE.
func (h *header) IsTrace() bool { return h.MethodIs(http.MethodTrace) }

// IsPatch returns true if request method is PATCH.
func (h *header) IsPatch() bool { return h.MethodIs(http.MethodPatch) }

// IsHTTP11 returns true if the request is HTTP/1.1.
func (h *header) IsHTTP11() bool { return !h.noHTTP11 }
