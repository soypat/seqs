package httpx

import "bufio"

type RequestHeader struct {
	hdr header
}

// Read reads request header from r.
//
// io.EOF is returned if r is closed before reading the first header byte.
func (h *RequestHeader) Read(r *bufio.Reader) error {
	h.hdr.trace("httpx:RqHdr.Read")
	return h.hdr.readLoop(r, true)
}

func (h *RequestHeader) Host() []byte { return h.hdr.Host() }

func (h *RequestHeader) Peek(key string) []byte { return h.hdr.Peek(key) }

func (h *RequestHeader) RawHeaders() []byte { return h.hdr.RawHeaders() }

func (h *RequestHeader) DisableNormalizing() { h.hdr.DisableNormalizing() }

func (h *RequestHeader) Method() []byte { return h.hdr.Method() }

func (h *RequestHeader) RequestURI() []byte { return h.hdr.RequestURI() }

func (h *RequestHeader) Protocol() []byte      { return h.hdr.Protocol() }
func (h *RequestHeader) UserAgent() []byte     { return h.hdr.UserAgent() }
func (h *RequestHeader) ContentType() []byte   { return h.hdr.ContentType() }
func (h *RequestHeader) DisableSpecialHeader() { h.hdr.DisableSpecialHeader() }

// String returns request header representation.
func (h *RequestHeader) String() string {
	return string(h.Header())
}

// Header returns request header representation.
//
// Headers that set as Trailer will not represent. Use TrailerHeader for trailers.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *RequestHeader) Header() []byte {
	h.hdr.bufKV.value = h.AppendBytes(h.hdr.bufKV.value[:0])
	return h.hdr.bufKV.value
}

// AppendBytes appends request header representation to dst and returns
// the extended dst.
func (h *RequestHeader) AppendBytes(dst []byte) []byte {
	dst = append(dst, h.Method()...)
	dst = append(dst, ' ')
	dst = append(dst, h.RequestURI()...)
	dst = append(dst, ' ')
	dst = append(dst, h.Protocol()...)
	dst = append(dst, strCRLF...)

	userAgent := h.UserAgent()
	if len(userAgent) > 0 && !h.hdr.disableSpecialHeader {
		dst = appendHeaderLine(dst, strUserAgent, b2s(userAgent))
	}

	host := h.Host()
	if len(host) > 0 && !h.hdr.disableSpecialHeader {
		dst = appendHeaderLine(dst, strHost, b2s(host))
	}

	contentType := h.ContentType()
	if !h.hdr.noDefaultContentType && len(contentType) == 0 && !h.hdr.ignoreBody() {
		contentType = append(contentType, strDefaultContentType...)
	}
	if len(contentType) > 0 && !h.hdr.disableSpecialHeader {
		dst = appendHeaderLine(dst, strContentType, b2s(contentType))
	}
	if len(h.hdr.contentLengthBytes) > 0 && !h.hdr.disableSpecialHeader {
		dst = appendHeaderLine(dst, strContentLength, b2s(h.hdr.contentLengthBytes))
	}

	return h.hdr.AppendReqRespCommon(dst)
}
