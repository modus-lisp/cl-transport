;;;; cl-transport.asd
;;;;
;;;; A uniform outbound transport: one DIAL that returns a binary stream + a close
;;;; thunk, whether the bytes go direct, through a SOCKS5 proxy, or through an HTTP
;;;; proxy's CONNECT — plus a registry for optional pluggable backends (e.g. native Tor
;;;; via the separate cl-tor-transport system).  Standalone: needs nothing beyond SBCL
;;;; (sb-bsd-sockets, sb-thread); no usocket, no bordeaux-threads, no Tor/TLS/crypto
;;;; stack unless a provider is loaded.

;;; The listeners, on their own.  glass needs exactly this and nothing else here, and
;;; glass has always been free of quicklisp -- which is what lets it be the display
;;; layer on bare metal.  Depending on the whole of cl-transport would have made a
;;; window system pull in usocket and bordeaux-threads to open a socket.
(defsystem "cl-transport/listeners"
  :description "TCP and UNIX listeners, socket files, peer credentials.  SBCL only, no
                third-party dependencies."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  ;; sb-posix ONLY where there is one.  Every sb-posix call in listeners.lisp sits
  ;; behind #+unix, so on Windows the symbols are never read and the contrib is never
  ;; wanted -- declaring it unconditionally would demand a package that SBCL does
  ;; provide there, but with a different set of symbols in it.
  :depends-on ("sb-bsd-sockets" #+unix "sb-posix")
  :serial t
  :components ((:module "src" :serial t :components ((:file "listeners")))))


;;; The connectivity stack, on its own.  STUN/TURN/ICE are how two peers behind NATs find
;;; a path to each other -- an IETF stack that predates WebRTC and is used by SIP too, so
;;; it belongs beside the transports rather than inside a WebRTC library.
;;;
;;; ITS OWN SYSTEM FOR /listeners' REASON, WITH A DIFFERENT ANSWER.  listeners is
;;; sb-bsd-sockets alone so a window system can open a socket without quicklisp.  This one
;;; genuinely needs bordeaux-threads (TURN runs a refresh timer and a transaction loop) and
;;; ironclad (MESSAGE-INTEGRITY is HMAC-SHA1; the long-term credential is MD5).  What it
;;; does not need is usocket -- so a caller wanting NAT traversal does not also get a
;;; SOCKS5 client, which declaring the whole of cl-transport would have handed them.
(defsystem "cl-transport/ice"
  :description "STUN, TURN and ICE: connectivity establishment between peers behind NATs.
                Independent of WebRTC, which is one consumer of it."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("sb-bsd-sockets" "bordeaux-threads" "ironclad" "uiop")
  :serial t
  :components ((:module "src" :serial t
                :components ((:file "ice-packages")   ; the package + its byte helpers
                             (:file "stun")           ; RFC 5389 framing, attributes, integrity
                             (:file "turn")           ; RFC 5766/8656 relay client
                             (:file "ice")))))        ; RFC 8445 agent: candidates, checks, selection

;;; Portable UDP and TCP on sb-bsd-sockets -- SBCL and hosted modus, which provides
;;; the same API -- with no usocket and no threads: a multi-peer UDP endpoint, a
;;; buffered TCP socket with deadline reads, and a wait across both.
(defsystem "cl-transport/sockets"
  :description "UDP (one socket, many peers) and TCP (buffered, deadline reads) on
                sb-bsd-sockets; runs on SBCL and on modus."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ((:feature :sbcl (:require "sb-bsd-sockets")))
  :components ((:module "src" :components ((:file "sockets")))))

;;; A TCP client engine with no I/O: segments in, segments out, time passed in.  For
;;; links that carry IP packets but have no kernel TCP behind them (an overlay that
;;; tunnels IPv6, a bare-metal NIC).  No dependencies at all, so modus can take it.
(defsystem "cl-transport/tcp"
  :description "A pure TCP client engine (RFC 9293 subset, IPv6 pseudo-header
                checksums): no sockets, no clock, no dependencies."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :components ((:module "src" :components ((:file "tcp")))))

(defsystem "cl-transport"
  :description "Uniform outbound transport (direct / SOCKS5 / HTTP CONNECT / pluggable
                backends) with a runtime backend registry.  SBCL only, no third-party code."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("sb-bsd-sockets" "cl-transport/listeners")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "util")          ; tiny byte helpers (self-contained)
     ;; The gate loads BEFORE transport.lisp because DIAL binds its *CARRIER*.
     (:file "gate-packages")
     (:file "gate-channel")  ; on modus, workers send their bookkeeping to its owner
     (:file "gate-names")    ; addresses learn the names they were resolved from
     (:file "gate-policy")   ; rules, carrier requirements, the config document
     (:file "gate-record")   ; what was asked for, and what was decided
     (:file "connect")       ; the one TCP connect every carrier goes through
     (:file "socks-client")  ; SOCKS5 CONNECT client (external proxy backend)
     (:file "http-connect-client")  ; HTTP CONNECT client (HTTPS_PROXY, corporate egress)
     (:file "transport")     ; DIAL + REGISTER-TRANSPORT (outbound)
     (:file "inbound")       ; EXPOSE + REGISTER-LISTENER (inbound; :tcp built in)
     (:file "gate")))))      ; the hook itself, and INITIALIZE
