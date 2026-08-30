;;;; src/transport.lisp — one DIAL for every backend.
;;;;
;;;; DIAL host port :transport X  ->  (values binary-stream closer-thunk)
;;;;
;;;; The whole point: callers (e.g. cl-consensus's connect-peer) get a uniform
;;;; binary stream + a close thunk and never branch on how the bytes travel.
;;;;
;;;;   :direct  plain TCP (usocket)                    — clearnet, no privacy
;;;;   :socks5  through an external SOCKS5 proxy        — system tor / any proxy
;;;;   <other>  a pluggable backend registered at runtime (REGISTER-TRANSPORT)
;;;;
;;;; :direct and :socks5 are built in and need no extra deps.  Other transports —
;;;; notably :tor — are OPTIONAL providers: load the provider (e.g. the cl-tor-transport
;;;; system) and it registers itself here.  Nothing Tor-specific lives in this system.
;;;; Outbound only for now.

(defpackage #:cl-transport
  (:use #:cl)
  (:local-nicknames (#:socks #:cl-transport.socks) (#:bt #:bordeaux-threads))
  (:export #:dial #:*default-transport* #:*socks-proxy*
           #:register-transport #:transport-available-p
           ;; inbound (src/inbound.lisp)
           #:expose #:register-listener #:listener-available-p
           ;; the listeners themselves (src/listeners.lisp), moved here from glass:
           ;; a display server had no business owning sockets, and every platform
           ;; assumption in the workspace was hiding in them.
           #:listener #:tcp-listener #:unix-listener #:open-listener
           #:tcp-listen #:unix-listen #:close-listener
           #:listener-kind #:listener-endpoint #:listener-open-p #:listener-socket
           #:listener-path #:listener-port #:listener-address #:listener-mode
           #:listener-peer-policy #:listener-refused #:listener-accept #:accept-stream
           #:runtime-dir #:socket-path #:socket-sibling
           #:*runtime-dir* #:*socket-file-mode* #:*socket-dir-mode*
           #:clear-stale-socket #:unix-socket-live-p
           #:peer-credentials #:peer-allowed-p #:peer-name #:socket-fd #:*peer-policy*
           #:open-connection #:parse-endpoint #:endpoint-string #:socket-unsent-bytes))

(in-package #:cl-transport)

(defparameter *default-transport* :direct
  "Transport used when DIAL is called without an explicit :TRANSPORT.")

(defparameter *socks-proxy* '("127.0.0.1" . 9050)
  "(host . port) of the SOCKS5 proxy for :SOCKS5 dials.")

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
  (or (member name '(:direct :socks5)) (and (gethash name *backends*) t)))

(defun dial (host port &key (transport *default-transport*) (timeout 20)
                            (proxy *socks-proxy*))
  "Open an outbound connection to HOST:PORT over TRANSPORT.  Returns
   (values stream closer): a binary stream usable like a socket stream, and a
   zero-arg thunk that tears the connection fully down.  Signals on failure, or if
   TRANSPORT has no registered backend (load its provider first)."
  ;; THE CARRIER IS DECLARED HERE, where it is actually chosen.  The gate below the
  ;; socket reads it, so a policy can say `require loom/* via tor\' and have that mean
  ;; something even about code that would rather open its own socket: that code carries
  ;; :RAW, which satisfies no requirement.
  (let ((cl-transport.gate:*carrier* transport))
   (case transport
    (:direct
     (let ((sock (usocket:socket-connect host port
                                         :element-type '(unsigned-byte 8) :timeout timeout)))
       (values (usocket:socket-stream sock)
               (lambda () (ignore-errors (usocket:socket-close sock))))))
    (:socks5
     (socks:socks5-connect host port :proxy-host (car proxy) :proxy-port (cdr proxy)
                                     :timeout timeout))
    (t
     (let ((fn (gethash transport *backends*)))
       (if fn
           (funcall fn host port timeout)
           (error "cl-transport: no backend registered for transport ~s — load its ~
                   provider first (e.g. the cl-tor-transport system for :tor)."
                  transport)))))))
