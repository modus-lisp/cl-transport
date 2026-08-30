;;;; cl-transport.asd
;;;;
;;;; A uniform outbound transport: one DIAL that returns a binary stream + a close
;;;; thunk, whether the bytes go direct or through a SOCKS5 proxy — plus a registry
;;;; for optional pluggable backends (e.g. native Tor via the separate cl-tor-transport
;;;; system).  Standalone: needs only usocket; no Tor/TLS/crypto stack unless a
;;;; provider is loaded.

(defsystem "cl-transport"
  :description "Uniform outbound transport (direct / SOCKS5 / pluggable backends) with
                a runtime backend registry.  Portable toward modus."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("usocket" "bordeaux-threads" "sb-bsd-sockets")
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
