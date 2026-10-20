;;;; src/transport.lisp — one DIAL for every backend.
;;;;
;;;; DIAL host port :transport X  ->  (values binary-stream closer-thunk)
;;;;
;;;; The whole point: callers (e.g. cl-consensus's connect-peer) get a uniform
;;;; binary stream + a close thunk and never branch on how the bytes travel.
;;;;
;;;;   :direct  plain TCP (sb-bsd-sockets)             — clearnet, no privacy
;;;;   :socks5  through an external SOCKS5 proxy        — system tor / any proxy
;;;;   :http-connect  through an HTTP proxy's CONNECT   — HTTPS_PROXY, corporate egress
;;;;   <other>  a pluggable backend registered at runtime (REGISTER-TRANSPORT)
;;;;
;;;; :direct and :socks5 are built in and need no extra deps.  Other transports —
;;;; notably :tor — are OPTIONAL providers: load the provider (e.g. the cl-tor-transport
;;;; system) and it registers itself here.  Nothing Tor-specific lives in this system.
;;;; Outbound only for now.

(defpackage #:cl-transport
  (:use #:cl)
  (:local-nicknames (#:socks #:cl-transport.socks)
                    (#:hc #:cl-transport.http-connect)
                    (#:cc #:cl-transport.connect))
  (:export #:dial #:*default-transport* #:*socks-proxy*
           #:*http-proxy* #:*http-proxy-authorization*
           #:register-transport #:transport-available-p
           ;; inbound (src/inbound.lisp)
           #:expose #:register-listener #:listener-available-p
           ;; The listener layer (src/listeners.lisp, its own package and its own
           ;; system) is IMPORTED and re-exported just below, not named here.  Naming
           ;; it in this :export would intern CL-TRANSPORT::SOCKET-PATH as a symbol of
           ;; its own, and IMPORT would then refuse it as a conflict -- the same trap
           ;; glass/fb's packages.lisp sets, for the same reason.
           ))

(in-package #:cl-transport)

;;; The listener layer, borrowed from its own package so that this one can speak of it.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (do-external-symbols (s (find-package '#:cl-transport.listeners))
    (import s '#:cl-transport)
    (export s '#:cl-transport)))

(defparameter *default-transport* :direct
  "Transport used when DIAL is called without an explicit :TRANSPORT.")

(defparameter *socks-proxy* '("127.0.0.1" . 9050)
  "(host . port) of the SOCKS5 proxy for :SOCKS5 dials.")

(defparameter *http-proxy* '("127.0.0.1" . 3128)
  "(host . port) of the HTTP proxy for :HTTP-CONNECT dials.")

(defparameter *http-proxy-authorization* nil
  "The Proxy-Authorization header value sent with every :HTTP-CONNECT CONNECT, for a
   proxy that asks for credentials (for example \"Basic <base64 of user:pass>\").
   NIL sends none.")

(defvar *backends* (make-hash-table :test 'eq)
  "Pluggable transport backends: keyword -> (lambda (host port timeout) ->
   (values stream closer)).  Populated by provider systems via REGISTER-TRANSPORT.")

(defun register-transport (name fn)
  "Register FN as the backend for transport keyword NAME.  FN takes (host port
   timeout) and returns (values binary-stream closer-thunk).  A provider system
   (e.g. cl-tor-transport for :TOR) calls this at load time."
  (check-type name keyword)
  (setf (gethash name *backends*) fn)
  name)

(defun transport-available-p (name)
  "True if DIAL can service transport NAME right now (built-in or a loaded provider)."
  (or (member name '(:direct :socks5 :http-connect)) (and (gethash name *backends*) t)))

(defun dial (host port &key (transport *default-transport*) (timeout 20) (proxy nil))
  "Open an outbound connection to HOST:PORT over TRANSPORT.  Returns
   (values stream closer): a binary stream usable like a socket stream, and a
   zero-arg thunk that tears the connection fully down.  Signals on failure, or if
   TRANSPORT has no registered backend (load its provider first).

   PROXY, a (host . port), names the proxy for a carrier that has one: *SOCKS-PROXY*
   for :SOCKS5 when NIL, *HTTP-PROXY* for :HTTP-CONNECT when NIL."
  ;; THE CARRIER IS DECLARED HERE, where it is actually chosen.  The gate below the
  ;; socket reads it, so a policy can say `require loom/* via tor\' and have that mean
  ;; something even about code that would rather open its own socket: that code carries
  ;; :RAW, which satisfies no requirement.
  (let ((cl-transport.gate:*carrier* transport))
   (case transport
    (:direct
     (multiple-value-bind (sock stream) (cc:connect-tcp host port :timeout timeout)
       (values stream (lambda () (ignore-errors (sb-bsd-sockets:socket-close sock))))))
    (:socks5
     (let ((proxy (or proxy *socks-proxy*)))
       (socks:socks5-connect host port :proxy-host (car proxy) :proxy-port (cdr proxy)
                                       :timeout timeout)))
    (:http-connect
     (let ((proxy (or proxy *http-proxy*)))
       (hc:http-connect host port :proxy-host (car proxy) :proxy-port (cdr proxy)
                                  :proxy-authorization *http-proxy-authorization*
                                  :timeout timeout)))
    (t
     (let ((fn (gethash transport *backends*)))
       (if fn
           (funcall fn host port timeout)
           (error "cl-transport: no backend registered for transport ~s — load its ~
                   provider first (e.g. the cl-tor-transport system for :tor)."
                  transport)))))))
