;;;; cl-transport.asd
;;;;
;;;; A uniform outbound transport: one DIAL that returns a binary stream + a close
;;;; thunk, whether the bytes go direct or through a SOCKS5 proxy — plus a registry
;;;; for optional pluggable backends (e.g. native Tor via the separate cl-tor-transport
;;;; system).  Standalone: needs only usocket; no Tor/TLS/crypto stack unless a
;;;; provider is loaded.

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

(defsystem "cl-transport"
  :description "Uniform outbound transport (direct / SOCKS5 / pluggable backends) with
                a runtime backend registry.  Portable toward modus."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("usocket" "bordeaux-threads" "sb-bsd-sockets" "cl-transport/listeners")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "util")          ; tiny byte helpers (self-contained)
     ;; The gate loads BEFORE transport.lisp because DIAL binds its *CARRIER*.
     (:file "gate-packages")
     (:file "gate-names")    ; addresses learn the names they were resolved from
     (:file "gate-policy")   ; rules, carrier requirements, the config document
     (:file "gate-record")   ; what was asked for, and what was decided
     (:file "socks-client")  ; SOCKS5 CONNECT client (external proxy backend)
     (:file "transport")     ; DIAL + REGISTER-TRANSPORT (outbound)
     (:file "inbound")       ; EXPOSE + REGISTER-LISTENER (inbound; :tcp built in)
     (:file "gate")))))      ; the hook itself, and INITIALIZE
