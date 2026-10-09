;;;; src/tcp.lisp -- a TCP client engine, pure: segments in, segments out.
;;;;
;;;; No sockets, no clock, no threads, no dependencies.  The caller hands it the
;;;; segments that arrived (as byte vectors) and the time in milliseconds, and sends
;;;; the segments it returns however its link carries them -- an overlay network
;;;; that tunnels IP packets (FIPS's IPv6 shim), a raw NIC driver, a userspace VPN.
;;;; That is what makes it a transport piece rather than a socket: it is TCP for the
;;;; places that have no kernel TCP to ask.  Portable CL, so it can run on modus.
;;;;
;;;; A TCP CLIENT, RFC 793/9293 in the subset a client needs: active open, the
;;;; ESTABLISHED data path with cumulative acks and an out-of-order buffer, our FIN
;;;; and theirs in either order, RST (only one that names an expected sequence
;;;; number), retransmission with exponential backoff (RFC 6298's shape, 1 s
;;;; initial RTO, no RTT sampling), the peer's window respected, a fixed congestion
;;;; window.  No window scaling, SACK, timestamps, Nagle, urgent data or passive
;;;; open.  Checksums use the IPv6 pseudo-header (RFC 8200 section 8.1); the
;;;; addresses are 16-byte vectors.
;;;;
;;;; Lessons from modus's bare-metal TCP (net/ip.lisp), where each one was a real
;;;; bug: the ISN and local port must vary per connection (a reused 4-tuple meets
;;;; TIME_WAIT); data is delivered strictly in order; a FIN takes its sequence
;;;; number AFTER the segment's own payload; sequence numbers wrap at 2^32.
;;;;
;;;;   (multiple-value-bind (c syn) (tcp-open local-ip remote-ip lport rport now :iss r :mss m) ...)
;;;;   (tcp-input c segment now)   -> events (:established :data :eof :reset :closed)
;;;;   (tcp-write c bytes) (tcp-close c) (tcp-read c)
;;;;   (tcp-output c now)          -> segments to send now

(defpackage #:cl-transport.tcp
  (:use #:cl)
  (:export #:tcp-open #:tcp-input #:tcp-output #:tcp-write #:tcp-read #:tcp-close
           #:tcp-eof-p #:tcp-closed-p #:tcp-next-due-ms
           #:tcp-conn #:tcp-conn-p #:tcp-conn-state #:tcp-conn-reset #:tcp-conn-lport #:tcp-conn-rport
           #:tcp-conn-local #:tcp-conn-remote #:tcp-conn-unacked
           #:build-tcp-segment #:parse-tcp-segment #:tcp-checksum
           #:tcp-segment #:seg-sport #:seg-dport #:seg-seq #:seg-ack #:seg-flags #:seg-window
           #:seg-data #:seg-mss
           #:+tcp-fin+ #:+tcp-syn+ #:+tcp-rst+ #:+tcp-psh+ #:+tcp-ack+
           #:seq+ #:seq- #:seq< #:seq<=))

(in-package #:cl-transport.tcp)

(defun bytes-of (&rest xs) (coerce xs '(simple-array (unsigned-byte 8) (*))))
(defun bytes-cat (&rest vs) (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) vs))
(defun bytes-slice (v start &optional end) (coerce (subseq v start end) '(simple-array (unsigned-byte 8) (*))))


(defconstant +tcp-default-mss+ 1220
  "The MSS offered when the caller names none: an IPv6 minimum MTU of 1280, less the
   40-byte IPv6 header and the 20-byte TCP header.")
(defconstant +tcp-window+ 65535 "The receive window we advertise (no scaling).")
(defconstant +tcp-cwnd-segments+ 16 "A fixed congestion window, in segments.")
(defconstant +tcp-rto-ms+ 1000)
(defconstant +tcp-rto-max-ms+ 60000)
(defconstant +tcp-max-retries+ 8)
(defconstant +tcp-ooo-max+ 256 "Out-of-order segments held at most.")

(defconstant +tcp-fin+ #x01) (defconstant +tcp-syn+ #x02) (defconstant +tcp-rst+ #x04)
(defconstant +tcp-psh+ #x08) (defconstant +tcp-ack+ #x10)

(defun seq+ (a n) (ldb (byte 32 0) (+ a n)))
(defun seq- (a b) "A - B as a signed distance, modulo 2^32."
  (let ((d (ldb (byte 32 0) (- a b)))) (if (>= d #x80000000) (- d #x100000000) d)))
(defun seq< (a b) (minusp (seq- a b)))
(defun seq<= (a b) (not (plusp (seq- a b))))

;;; --- segments -----------------------------------------------------------------------

(defun %be16 (v o) (logior (ash (aref v o) 8) (aref v (1+ o))))
(defun %be32 (v o) (logior (ash (%be16 v o) 16) (%be16 v (+ o 2))))
(defun %put16 (v o n) (setf (aref v o) (ldb (byte 8 8) n) (aref v (1+ o)) (ldb (byte 8 0) n)))
(defun %put32 (v o n) (%put16 v o (ldb (byte 16 16) n)) (%put16 v (+ o 2) (ldb (byte 16 0) n)))

(defun tcp-checksum (src dst segment)
  "The TCP checksum over the IPv6 pseudo-header (RFC 8200 section 8.1) and SEGMENT."
  (let ((sum 0))
    (flet ((add16 (v o) (incf sum (if (< (1+ o) (length v)) (%be16 v o) (ash (aref v o) 8)))))
      (loop for o from 0 below 16 by 2 do (add16 src o) (add16 dst o))
      (incf sum (ldb (byte 16 16) (length segment)))
      (incf sum (ldb (byte 16 0) (length segment)))
      (incf sum 6)
      (loop for o from 0 below (length segment) by 2 do (add16 segment o)))
    (loop while (> sum #xffff) do (setf sum (+ (ldb (byte 16 0) sum) (ash sum -16))))
    (ldb (byte 16 0) (lognot sum))))

(defun build-tcp-segment (src dst sport dport seq ack flags window data &key mss)
  "A TCP segment from SRC to DST (16-byte IPv6 addresses), checksum filled in.
   MSS, when given, adds the MSS option (a SYN)."
  (let* ((opt (if mss 4 0))
         (seg (make-array (+ 20 opt (length data)) :element-type '(unsigned-byte 8) :initial-element 0)))
    (%put16 seg 0 sport) (%put16 seg 2 dport)
    (%put32 seg 4 seq) (%put32 seg 8 ack)
    (setf (aref seg 12) (ash (/ (+ 20 opt) 4) 4) (aref seg 13) flags)
    (%put16 seg 14 window)
    (when mss (setf (aref seg 20) 2 (aref seg 21) 4) (%put16 seg 22 mss))
    (replace seg data :start1 (+ 20 opt))
    (%put16 seg 16 (tcp-checksum src dst seg))
    seg))

(defstruct (tcp-segment (:conc-name seg-)) sport dport seq ack flags window data mss)

(defun parse-tcp-segment (src dst seg)
  "SEG as a TCP-SEGMENT if it is well formed and its checksum is right, else NIL.
   SRC and DST are the addresses it travelled between (the pseudo-header)."
  (when (>= (length seg) 20)
    (let ((off (* 4 (ash (aref seg 12) -4))))
      (when (and (<= 20 off (length seg)) (zerop (tcp-checksum src dst seg)))
        (let ((mss nil))
          ;; options: only MSS matters to us
          (loop with i = 20
                while (< i off)
                do (let ((kind (aref seg i)))
                     (cond ((= kind 0) (return))
                           ((= kind 1) (incf i))
                           ((>= (1+ i) off) (return))
                           (t (let ((len (aref seg (1+ i))))
                                (when (< len 2) (return))
                                (when (and (= kind 2) (= len 4) (<= (+ i 4) off)) (setf mss (%be16 seg (+ i 2))))
                                (incf i len))))))
          (make-tcp-segment :sport (%be16 seg 0) :dport (%be16 seg 2) :seq (%be32 seg 4) :ack (%be32 seg 8)
                            :flags (aref seg 13) :window (%be16 seg 14) :data (bytes-slice seg off)
                            :mss mss))))))

;;; --- the connection -------------------------------------------------------------------

(defstruct (tcp-conn (:constructor %make-tcp-conn))
  local remote lport rport           ; addresses (16 bytes each) and ports
  (state :syn-sent)                  ; :syn-sent :established :closed
  iss snd-una snd-nxt (snd-wnd 1024) (peer-mss 536) (mss +tcp-default-mss+)
  rcv-nxt
  (outq (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (unacked '())                      ; ((seq flags data) ...) oldest first
  (rto +tcp-rto-ms+) (rtx-at nil) (retries 0)
  (ooo '())                          ; ((seq . data) ...) out of order
  (fin-at nil)                       ; the sequence number of a FIN that came early
  (inbox '())                        ; delivered byte vectors, oldest first
  (close-requested nil) (fin-sent nil) (fin-acked nil) (fin-received nil)
  (ack-due nil) (reset nil))

(defun tcp-open (local remote lport rport now &key (iss (random #x100000000)) (mss +tcp-default-mss+))
  "Start a connection: returns (values conn segments), the segments being the SYN.
   ISS should come from a cryptographic source when the path is not trusted (an
   off-path attacker who can guess it can inject data); the default is CL:RANDOM.
   MSS is what we offer: the largest segment our link carries in one packet."
  (let ((c (%make-tcp-conn :local local :remote remote :lport lport :rport rport :mss mss
                           :iss iss :snd-una iss :snd-nxt (seq+ iss 1))))
    (setf (tcp-conn-unacked c) (list (list iss +tcp-syn+ (bytes-of)))
          (tcp-conn-rtx-at c) (+ now (tcp-conn-rto c)))
    (values c (list (%seg c iss +tcp-syn+ (bytes-of) :mss mss)))))

(defun %seg (c seq flags data &key mss)
  (build-tcp-segment (tcp-conn-local c) (tcp-conn-remote c) (tcp-conn-lport c) (tcp-conn-rport c)
                     seq (or (tcp-conn-rcv-nxt c) 0)
                     (if (tcp-conn-rcv-nxt c) (logior flags +tcp-ack+) flags)
                     +tcp-window+ data :mss mss))

(defun tcp-write (c bytes)
  "Queue BYTES to send."
  (loop for b across bytes do (vector-push-extend b (tcp-conn-outq c))))

(defun tcp-close (c) "Send our FIN once everything queued has gone." (setf (tcp-conn-close-requested c) t))

(defun tcp-read (c)
  "Everything delivered in order since the last call, as one byte vector."
  (let ((parts (tcp-conn-inbox c)))
    (setf (tcp-conn-inbox c) '())
    (apply #'bytes-cat parts)))

(defun tcp-eof-p (c) "The peer's FIN has been delivered." (tcp-conn-fin-received c))

(defun tcp-closed-p (c)
  (or (eq (tcp-conn-state c) :closed)
      (and (tcp-conn-fin-received c) (tcp-conn-fin-acked c))))

(defun %deliver-in-order (c)
  (loop for hit = (find (tcp-conn-rcv-nxt c) (tcp-conn-ooo c) :key #'car)
        while hit
        do (setf (tcp-conn-ooo c) (remove hit (tcp-conn-ooo c)))
           (%accept-data c (cdr hit))))

(defun %accept-data (c data)
  (when (plusp (length data))
    (setf (tcp-conn-inbox c) (append (tcp-conn-inbox c) (list data))
          (tcp-conn-rcv-nxt c) (seq+ (tcp-conn-rcv-nxt c) (length data)))))

(defun tcp-input (c segment now)
  "A segment from the peer (bytes, checksum unverified).  Returns events: :established,
   :data (bytes are waiting for TCP-READ), :eof (their FIN), :reset, :closed.  What it
   wants to send goes out at the next TCP-OUTPUT."
  (let ((s (parse-tcp-segment (tcp-conn-remote c) (tcp-conn-local c) segment))
        (events '()))
    (when (or (null s) (/= (seg-sport s) (tcp-conn-rport c)) (/= (seg-dport s) (tcp-conn-lport c))
              (eq (tcp-conn-state c) :closed))
      (return-from tcp-input nil))
    (let ((flags (seg-flags s)))
      (when (logtest flags +tcp-rst+)
        ;; accept a reset only if it names a sequence number we could be expecting
        (when (or (eq (tcp-conn-state c) :syn-sent)
                  (and (tcp-conn-rcv-nxt c) (seq<= (tcp-conn-rcv-nxt c) (seg-seq s))
                       (seq< (seg-seq s) (seq+ (tcp-conn-rcv-nxt c) +tcp-window+))))
          (setf (tcp-conn-state c) :closed (tcp-conn-reset c) t)
          (return-from tcp-input (list :reset)))
        (return-from tcp-input nil))
      (case (tcp-conn-state c)
        (:syn-sent
         (when (and (logtest flags +tcp-syn+) (logtest flags +tcp-ack+)
                    (= (seg-ack s) (seq+ (tcp-conn-iss c) 1)))
           (setf (tcp-conn-rcv-nxt c) (seq+ (seg-seq s) 1)
                 (tcp-conn-snd-una c) (seg-ack s)
                 (tcp-conn-snd-wnd c) (seg-window s)
                 (tcp-conn-peer-mss c) (min (tcp-conn-mss c) (or (seg-mss s) 536))
                 (tcp-conn-unacked c) '() (tcp-conn-rtx-at c) nil
                 (tcp-conn-rto c) +tcp-rto-ms+ (tcp-conn-retries c) 0
                 (tcp-conn-state c) :established (tcp-conn-ack-due c) t)
           (push :established events)))
        (:established
         ;; the ack
         (when (logtest flags +tcp-ack+)
           (let ((ack (seg-ack s)))
             (when (and (seq< (tcp-conn-snd-una c) ack) (seq<= ack (tcp-conn-snd-nxt c)))
               (setf (tcp-conn-snd-una c) ack
                     (tcp-conn-unacked c)
                     (remove-if (lambda (u) (seq<= (seq+ (first u) (%seg-len u)) ack)) (tcp-conn-unacked c))
                     (tcp-conn-rto c) +tcp-rto-ms+ (tcp-conn-retries c) 0
                     (tcp-conn-rtx-at c) (and (tcp-conn-unacked c) (+ now +tcp-rto-ms+)))
               (when (and (tcp-conn-fin-sent c) (= ack (tcp-conn-snd-nxt c)))
                 (setf (tcp-conn-fin-acked c) t)))
             (setf (tcp-conn-snd-wnd c) (seg-window s))))
         ;; the data and the FIN, in sequence space
         (let* ((data (seg-data s)) (seq (seg-seq s)) (fin (logtest flags +tcp-fin+)))
           (when (or (plusp (length data)) fin) (setf (tcp-conn-ack-due c) t))
           ;; trim what we already have
           (let ((behind (seq- (tcp-conn-rcv-nxt c) seq)))
             (when (and (plusp behind) (plusp (length data)))
               (if (>= behind (length data))
                   (setf data (bytes-of) seq (tcp-conn-rcv-nxt c))
                   (setf data (bytes-slice data behind) seq (tcp-conn-rcv-nxt c)))))
           (cond
             ((= seq (tcp-conn-rcv-nxt c))
              (let ((before (tcp-conn-rcv-nxt c)))
                (%accept-data c data)
                (%deliver-in-order c)
                (when (/= before (tcp-conn-rcv-nxt c)) (push :data events)))
              nil)
             ((and (seq< (tcp-conn-rcv-nxt c) seq) (plusp (length data))
                   (< (length (tcp-conn-ooo c)) +tcp-ooo-max+)
                   (not (find seq (tcp-conn-ooo c) :key #'car)))
              (push (cons seq data) (tcp-conn-ooo c))))
           ;; a FIN takes the sequence number after its segment's payload, and it
           ;; counts only once everything before it has arrived: one that comes
           ;; ahead of a gap is remembered until the gap fills
           (when (and fin (not (tcp-conn-fin-received c)))
             (setf (tcp-conn-fin-at c) (seq+ (seg-seq s) (length (seg-data s)))))
           (when (and (tcp-conn-fin-at c) (not (tcp-conn-fin-received c))
                      (= (tcp-conn-rcv-nxt c) (tcp-conn-fin-at c)))
             (setf (tcp-conn-fin-received c) t (tcp-conn-rcv-nxt c) (seq+ (tcp-conn-rcv-nxt c) 1)
                   (tcp-conn-ack-due c) t)
             (push :eof events))))))
    (when (tcp-closed-p c)
      (setf (tcp-conn-state c) :closed)
      (push :closed events))
    (nreverse events)))

(defun %seg-len (u)
  "Sequence space an unacked entry takes: its data, plus one for SYN or FIN."
  (+ (length (third u)) (if (logtest (second u) (logior +tcp-syn+ +tcp-fin+)) 1 0)))

(defun tcp-output (c now)
  "Segments to send now: retransmission, new data within the windows, our FIN, a
   bare ack.  Returns (values segments events); an event :reset means the peer
   stopped answering and the connection is closed."
  (let ((out '()))
    (when (eq (tcp-conn-state c) :closed) (return-from tcp-output (values nil nil)))
    ;; retransmission: the oldest unacked segment
    (when (and (tcp-conn-rtx-at c) (>= now (tcp-conn-rtx-at c)) (tcp-conn-unacked c))
      (if (>= (tcp-conn-retries c) +tcp-max-retries+)
          (progn (setf (tcp-conn-state c) :closed (tcp-conn-reset c) t)
                 (return-from tcp-output
                   (values (list (%seg c (tcp-conn-snd-nxt c) +tcp-rst+ (bytes-of))) (list :reset))))
          (destructuring-bind (seq flags data) (first (tcp-conn-unacked c))
            (push (%seg c seq flags data :mss (and (logtest flags +tcp-syn+) (tcp-conn-mss c))) out)
            (incf (tcp-conn-retries c))
            (setf (tcp-conn-rto c) (min +tcp-rto-max-ms+ (* 2 (tcp-conn-rto c)))
                  (tcp-conn-rtx-at c) (+ now (tcp-conn-rto c))
                  (tcp-conn-ack-due c) nil))))
    (when (eq (tcp-conn-state c) :established)
      ;; new data, while both windows allow
      (loop
        (let* ((in-flight (seq- (tcp-conn-snd-nxt c) (tcp-conn-snd-una c)))
               (room (- (min (tcp-conn-snd-wnd c) (* +tcp-cwnd-segments+ (tcp-conn-peer-mss c))) in-flight))
               (queued (length (tcp-conn-outq c)))
               (n (min queued (tcp-conn-peer-mss c) (max 0 room))))
          (when (<= n 0) (return))
          (let* ((data (subseq (tcp-conn-outq c) 0 n))
                 (data (coerce data '(simple-array (unsigned-byte 8) (*))))
                 (seq (tcp-conn-snd-nxt c))
                 (flags (logior +tcp-psh+)))
            (let ((rest (subseq (tcp-conn-outq c) n)))
              (setf (fill-pointer (tcp-conn-outq c)) 0)
              (loop for b across rest do (vector-push-extend b (tcp-conn-outq c))))
            (setf (tcp-conn-unacked c) (append (tcp-conn-unacked c) (list (list seq flags data)))
                  (tcp-conn-snd-nxt c) (seq+ seq n))
            (unless (tcp-conn-rtx-at c) (setf (tcp-conn-rtx-at c) (+ now (tcp-conn-rto c))))
            (push (%seg c seq flags data) out)
            (setf (tcp-conn-ack-due c) nil))))
      ;; our FIN, after everything queued
      (when (and (tcp-conn-close-requested c) (not (tcp-conn-fin-sent c))
                 (zerop (length (tcp-conn-outq c))))
        (let ((seq (tcp-conn-snd-nxt c)))
          (setf (tcp-conn-unacked c) (append (tcp-conn-unacked c) (list (list seq +tcp-fin+ (bytes-of))))
                (tcp-conn-snd-nxt c) (seq+ seq 1)
                (tcp-conn-fin-sent c) t)
          (unless (tcp-conn-rtx-at c) (setf (tcp-conn-rtx-at c) (+ now (tcp-conn-rto c))))
          (push (%seg c seq +tcp-fin+ (bytes-of)) out)
          (setf (tcp-conn-ack-due c) nil)))
      ;; a bare ack, if nothing above carried one
      (when (tcp-conn-ack-due c)
        (push (%seg c (tcp-conn-snd-nxt c) 0 (bytes-of)) out)
        (setf (tcp-conn-ack-due c) nil)))
    (values (nreverse out) nil)))

(defun tcp-next-due-ms (c)
  "When TCP-OUTPUT next has a timer to serve, or NIL."
  (tcp-conn-rtx-at c))
