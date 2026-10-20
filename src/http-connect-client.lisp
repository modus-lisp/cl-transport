;;;; src/http-connect-client.lisp — an HTTP CONNECT client (RFC 9110 §9.3.6).
;;;;
;;;; Dials HOST:PORT through an HTTP proxy that tunnels with CONNECT: the usual
;;;; `HTTPS_PROXY' of a corporate network, and what a Squid or a cloud egress proxy
;;;; speaks.  After the proxy's 2xx the socket is a plain byte pipe to HOST:PORT, so a
;;;; TLS client on top of it (seal) is end to end with the origin and the proxy sees
;;;; only ciphertext.  Nothing here is TLS.
;;;;
;;;; The reply is read one byte at a time, up to the blank line that ends the header.
;;;; A buffered read would take bytes past it, and those belong to the tunnel.

(defpackage #:cl-transport.http-connect
  (:use #:cl)
  (:local-nicknames (#:u #:cl-transport.util))
  (:export #:http-connect))

(in-package #:cl-transport.http-connect)

(defun %read-line-crlf (s)
  "One CRLF-terminated line of the reply, without the CRLF.  Reads byte by byte, so
   nothing past the line is consumed."
  (let ((out (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte s nil nil)
          do (cond ((null b) (error "http-connect: proxy closed the connection mid-reply"))
                   ((= b 10) (return))
                   ((= b 13))
                   ((> (fill-pointer out) 8192) (error "http-connect: reply header too long"))
                   (t (vector-push-extend b out))))
    (map 'string #'code-char out)))

(defun %status-code (line)
  "The three-digit code of a status line `HTTP/1.1 200 Connection established'."
  (let* ((sp (position #\Space line))
         (code (and sp (<= (+ sp 4) (length line)) (parse-integer line :start (1+ sp)
                                                              :end (+ sp 4)
                                                              :junk-allowed t))))
    (or code (error "http-connect: malformed status line ~s" line))))

(defun http-connect (host port &key (proxy-host "127.0.0.1") (proxy-port 3128)
                                    proxy-authorization (timeout 20))
  "CONNECT to HOST:PORT through the HTTP proxy at PROXY-HOST:PROXY-PORT.  Returns
   (values stream closer): a binary stream carrying the tunnel and a thunk that tears
   it down.  PROXY-AUTHORIZATION, when given, is sent as the Proxy-Authorization
   header value (for example `Basic <base64>').  Signals if the proxy refuses."
  (let* ((sock (usocket:socket-connect proxy-host proxy-port
                                       :element-type '(unsigned-byte 8) :timeout timeout))
         (s (usocket:socket-stream sock))
         (target (format nil "~a:~d" host port)))
    (handler-case
        (progn
          (write-sequence
           (u:ascii->bytes
            (format nil "CONNECT ~a HTTP/1.1~c~cHost: ~a~c~c~@[Proxy-Authorization: ~a~c~c~]~c~c"
                    target #\Return #\Newline target #\Return #\Newline
                    proxy-authorization #\Return #\Newline #\Return #\Newline))
           s)
          (force-output s)
          (let ((status (%status-code (%read-line-crlf s))))
            ;; Every header line up to the blank one is read and discarded: the tunnel
            ;; starts after it, whatever the proxy sent.
            (loop for line = (%read-line-crlf s) until (zerop (length line)))
            (unless (<= 200 status 299)
              (error "http-connect: proxy refused ~a with ~d" target status)))
          (values s (lambda () (ignore-errors (usocket:socket-close sock)))))
      (serious-condition (e)
        (ignore-errors (usocket:socket-close sock))
        (error e)))))
