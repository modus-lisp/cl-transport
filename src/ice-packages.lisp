;;;; src/ice-packages.lisp — the connectivity stack's package, and the byte helpers it needs.
;;;;
;;;; ==================================================================================
;;;; WHY THIS IS IN cl-transport AND NOT IN A WebRTC LIBRARY
;;;; ==================================================================================
;;;;
;;;; STUN (RFC 5389), TURN (RFC 5766/8656) and ICE (RFC 8445) are the IETF connectivity
;;;; stack: how two peers behind NATs find a path to each other.  They predate WebRTC,
;;;; they are used by SIP and by anything else that has to get a datagram across a
;;;; symmetric NAT, and WebRTC is one CONSUMER of them rather than their owner.  They
;;;; lived in `webrtc-data' for the ordinary reason — that is who needed them first.
;;;;
;;;; The code agreed with the RFCs, which is what made the move worth doing rather than
;;;; worth arguing about.  Measured before anything was touched:
;;;;
;;;;   * turn.lisp names ICE in EIGHT places and every one is a comment or a docstring.
;;;;     There is no code-level dependency from TURN on ICE at all.
;;;;   * stun.lisp is a 95-line leaf.  Its only nod to ICE is two attribute CONSTANTS
;;;;     (+attr-ice-controlled+ #x8029, +attr-ice-controlling+ #x802A), which are entries
;;;;     in the STUN attribute registry and not calls into anything.
;;;;   * neither file reads *STUN-SERVERS*, *TURN-DEBUG* or +TURN-RELAY-PRIORITY+.  Those
;;;;     are ICE's configuration, they stay with ICE, and their absence here is what makes
;;;;     the cut clean in BOTH directions rather than only outward.
;;;;   * the gateway that drives all of this (glass-webrtc) names 23 ICE symbols and
;;;;     ZERO from STUN or TURN.  It cannot notice this move.
;;;;
;;;; ==================================================================================
;;;; ITS OWN SYSTEM, FOR THE REASON /listeners IS ITS OWN SYSTEM
;;;; ==================================================================================
;;;;
;;;; cl-transport.asd already carries that argument: `cl-transport/listeners' depends on
;;;; sb-bsd-sockets alone so that glass — which has always been free of quicklisp, which
;;;; is what lets it be the display layer on bare metal — can open a socket without
;;;; pulling usocket and bordeaux-threads into a window system.
;;;;
;;;; The same reasoning applies here and gives a DIFFERENT answer, so it is worth stating
;;;; rather than copying: this stack genuinely needs bordeaux-threads (TURN keeps a refresh
;;;; timer and a transaction loop) and ironclad (MESSAGE-INTEGRITY is HMAC-SHA1, and TURN's
;;;; long-term credential is MD5(user:realm:pass)).  What it does NOT need is usocket, and
;;;; declaring the whole of cl-transport would have added it.  So: its own system, three
;;;; dependencies, and a caller that wants NAT traversal does not get a SOCKS5 client.
;;;;
;;;; ==================================================================================
;;;; THE BYTE HELPERS ARE COPIED, NOT SHARED, AND THAT IS DELIBERATE FOR NOW
;;;; ==================================================================================
;;;;
;;;; cl-transport.util already has these shapes under other names — OCTETS for U8VEC, CAT
;;;; for CAT-BYTES, ASCII->BYTES for ASCII — and one real collision: U8 is a FUNCTION there
;;;; and a TYPE here, so `(make-array n :element-type 'u8)' would silently mean something
;;;; else.  Unifying them is a rename across 443 lines of protocol code in the same commit
;;;; that moves it, which is exactly how a move stops being provably behaviour-preserving.
;;;;
;;;; So the six lines are duplicated, on purpose, and this comment is the marker for the
;;;; follow-up: when ICE lands here too, webrtc-data's util.lisp loses its only remaining
;;;; readers for these five names and they can be reconciled in one pass, with the protocol
;;;; code already at rest.

(defpackage #:cl-transport.ice
  (:use #:cl)
  (:local-nicknames (#:ic #:ironclad))
  (:documentation "STUN, TURN and ICE: getting a datagram between two peers behind NATs.")
  (:export
   ;; ---- byte helpers (see the header: copied from webrtc-data/src/util.lisp) ----
   #:u8 #:u8vec #:as-u8vec #:cat-bytes #:ascii #:bytes->ascii
   #:u8! #:u16be #:u32be #:rd-u16be #:rd-u32be #:random-bytes
   ;; ---- the protocols: everything stun.lisp and turn.lisp define ----
   #:+attr-channel-number+ #:+attr-data+ #:+attr-error-code+ #:+attr-fingerprint+
   #:+attr-ice-controlled+ #:+attr-ice-controlling+ #:+attr-lifetime+ #:+attr-message-integrity+
   #:+attr-nonce+ #:+attr-priority+ #:+attr-realm+ #:+attr-requested-transport+
   #:+attr-software+ #:+attr-use-candidate+ #:+attr-username+ #:+attr-xor-mapped-address+
   #:+attr-xor-peer-address+ #:+attr-xor-relayed-address+ #:+binding-request+ #:+binding-success+
   #:+stun-magic+ #:+turn-allocate+ #:+turn-allocate-error+ #:+turn-allocate-success+
   #:+turn-channel-bind+ #:+turn-channel-bind-success+ #:+turn-channel-max+ #:+turn-channel-min+
   #:+turn-create-perm+ #:+turn-create-perm-success+ #:+turn-data-indication+ #:+turn-refresh+
   #:+turn-refresh-success+ #:+turn-send-indication+ #:crc32 #:decode-stun
   #:encode-stun #:hmac-sha1 #:make-turn-alloc #:parse-xor-mapped-address
   #:stun-attr #:stun-transaction-id #:stun-username-key #:turn-alloc
   #:turn-alloc-binding #:turn-alloc-chan->peer #:turn-alloc-key #:turn-alloc-lifetime
   #:turn-alloc-mapped-ip #:turn-alloc-mapped-port #:turn-alloc-next-channel #:turn-alloc-nonce
   #:turn-alloc-p #:turn-alloc-pass #:turn-alloc-peer->chan #:turn-alloc-perms
   #:turn-alloc-realm #:turn-alloc-refresh-thread #:turn-alloc-relay-ip #:turn-alloc-relay-port
   #:turn-alloc-resp #:turn-alloc-resp-cv #:turn-alloc-resp-lock #:turn-alloc-server-host
   #:turn-alloc-server-port #:turn-alloc-socket #:turn-alloc-user #:turn-allocate
   #:turn-channel-bind #:turn-channeldata-p #:turn-create-permission #:turn-deliver-control
   #:turn-install-peer #:turn-long-term-key #:turn-refresh #:turn-refresh-via-loop
   #:turn-start-refresh #:turn-wrap-channeldata #:turn-wrap-send-indication #:xor-mapped-address
   ;; ---- ICE (RFC 8445) --------------------------------------------------------------
   #:ice-candidate #:ice-candidate-p #:make-ice-candidate
   #:ice-candidate-foundation #:ice-candidate-component #:ice-candidate-transport
   #:ice-candidate-priority #:ice-candidate-ip #:ice-candidate-port
   #:ice-candidate-type
   ;; %TURN-TXN-LOOP and %FROM-TURN-SERVER-P are NO LONGER EXPORTED: they were, for one
   ;; commit, only because ice.lisp lived in another package and had to reach them.  It is
   ;; here now, so they are internal again, which is what the percent prefix always meant.
   #:*stun-servers* #:*turn-debug* #:+ice-chars+ #:+turn-relay-priority+
   #:ice-agent #:ice-agent-check-thread #:ice-agent-created-at #:ice-agent-last-rx
   #:ice-agent-local-ip #:ice-agent-local-pwd #:ice-agent-local-ufrag #:ice-agent-on-media
   #:ice-agent-on-packet #:ice-agent-p #:ice-agent-peer #:ice-agent-port
   #:ice-agent-relay-ip #:ice-agent-relay-port #:ice-agent-remote-candidates #:ice-agent-remote-pwd
   #:ice-agent-remote-ufrag #:ice-agent-route-changes #:ice-agent-selected-at #:ice-agent-selected-first
   #:ice-agent-socket #:ice-agent-srflx-ip #:ice-agent-srflx-port #:ice-agent-stop
   #:ice-agent-thread #:ice-agent-turn #:ice-bind-relay-peer-async #:ice-close
   #:ice-dispatch #:ice-gather-relay #:ice-gather-srflx #:ice-handle-stun
   #:ice-local-end-type #:ice-note-peer #:ice-offered-counts #:ice-relayed-inner
   #:ice-relayed-inner-send #:ice-remote-end-type #:ice-route-label #:ice-selection-secs
   #:ice-send #:ice-send-to-peer #:ice-serve #:ice-silent-secs
   #:ice-start-checks #:ice-string #:local-ipv4 #:make-ice
   #:make-ice-agent #:resolve-host #:tdbg #:ice-accept-remote))

(in-package #:cl-transport.ice)

;;; The helpers, verbatim from webrtc-data/src/util.lisp.  U8VEC is both a TYPE and a
;;; FUNCTION and both are used — the type by `:element-type', the function to make one.
(deftype u8 () '(unsigned-byte 8))
(deftype u8vec () '(simple-array (unsigned-byte 8) (*)))
(defun u8vec (n &optional (init 0)) (make-array n :element-type 'u8 :initial-element init))
(defun as-u8vec (seq) (coerce seq 'u8vec))
(defun cat-bytes (&rest seqs) (apply #'concatenate 'u8vec seqs))
(defun ascii (s) (map 'u8vec #'char-code s))
(defun bytes->ascii (v) (map 'string #'code-char v))
(defun u8! (n) (logand n #xff))

;;; big-endian integer read/write
(defun u16be (n) (as-u8vec (list (u8! (ash n -8)) (u8! n))))
(defun u32be (n) (as-u8vec (list (u8! (ash n -24)) (u8! (ash n -16)) (u8! (ash n -8)) (u8! n))))
(defun rd-u16be (v off) (logior (ash (aref v off) 8) (aref v (1+ off))))
(defun rd-u32be (v off) (logior (ash (aref v off) 24) (ash (aref v (1+ off)) 16)
                                (ash (aref v (+ off 2)) 8) (aref v (+ off 3))))

;;; /dev/urandom, with ironclad's Fortuna as the fallback for a platform that has no such
;;; file — a TURN transaction id has to be unguessable, so this is not a place to degrade
;;; quietly to something weaker without saying so.
(defun random-bytes (n)
  (handler-case
      (with-open-file (f "/dev/urandom" :element-type 'u8) (let ((b (u8vec n))) (read-sequence b f) b))
    (error () (ic:random-data n (ic:make-prng :fortuna)))))
