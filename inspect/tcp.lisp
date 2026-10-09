;;;; tcp.lisp — the TCP engine does what TCP says, against a scripted peer.
;;;;
;;;;   sbcl --script inspect/tcp.lisp
;;;;
;;;; The engine has no passive open and nothing here may open a raw socket, so the
;;;; far end is a script written with the same segment codec.  The checksum, the
;;;; one thing the codec could get wrong in both directions at once, is checked
;;;; against an independent computation (the expected value below came from a
;;;; Python implementation of RFC 8200's pseudo-header, not from this code).

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:directory ,(merge-pathnames "../" here)) :inherit-configuration)))
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport/tcp")))

(defpackage #:tcp-test (:use #:cl #:cl-transport.tcp)) (in-package #:tcp-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got &optional detail)
  (if got (progn (incf *pass*) (format t "  [pass] ~a~@[ — ~a~]~%" name detail))
      (progn (incf *fail*) (format t "  [FAIL] ~a~@[ — ~a~]~%" name detail)))
  (finish-output) got)
(defun head (s) (format t "~%== ~a ==~%" s) (finish-output))

(defun v (&rest xs) (coerce xs '(simple-array (unsigned-byte 8) (*))))
(defun ascii (s) (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))
(defun addr (b) (let ((a (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref a 0) #xfd (aref a 15) b) a))
(defparameter *us* (addr 1))
(defparameter *them* (addr 2))

;;; The peer: a few lines of a server, in terms of the codec.
(defun peer-seg (seq ack flags data &key (window 65535) mss)
  "A segment from the peer (port 80) to us (port 40000)."
  (build-tcp-segment *them* *us* 80 40000 seq ack flags window data :mss mss))
(defun mine (seg) (parse-tcp-segment *us* *them* seg))

(defun open-conn (&key (iss 1000) (their-iss 5000) (now 0) (mss 1000))
  "A connection through the handshake.  Returns (values conn their-next our-next)."
  (multiple-value-bind (c syns) (tcp-open *us* *them* 40000 80 now :iss iss :mss mss)
    (let ((syn (mine (first syns))))
      (tcp-input c (peer-seg their-iss (seq+ (seg-seq syn) 1) (logior +tcp-syn+ +tcp-ack+) (v) :mss 1400) now)
      (tcp-output c now)                                     ; the handshake's ack
      (values c (seq+ their-iss 1) (seq+ iss 1)))))

(head "checksum")
;; TCP SYN from fd00::1 port 40000 to fd00::2 port 80, seq 1000, window 65535,
;; MSS 1220: checksum computed independently (Python, RFC 8200 pseudo-header) = 0xfe99.
(let ((seg (build-tcp-segment *us* *them* 40000 80 1000 0 +tcp-syn+ 65535 (v) :mss 1220)))
  (ok "the checksum matches an independent computation"
      (= (logior (ash (aref seg 16) 8) (aref seg 17)) #xfe99)
      (format nil "#x~4,'0x" (logior (ash (aref seg 16) 8) (aref seg 17))))
  (ok "the segment parses back" (mine seg))
  (let ((bad (copy-seq seg))) (setf (aref bad 21) (logxor (aref bad 21) 1))
    (ok "a corrupted segment is refused" (null (mine bad))))
  (ok "a segment for other addresses is refused (pseudo-header)"
      (null (parse-tcp-segment *us* (addr 3) seg))))
(let ((odd (build-tcp-segment *us* *them* 1 2 3 4 +tcp-ack+ 100 (v 1 2 3))))
  (ok "an odd-length segment checksums and parses" (and (mine odd) (equalp (seg-data (mine odd)) (v 1 2 3)))))

(head "handshake")
(multiple-value-bind (c syns) (tcp-open *us* *them* 40000 80 0 :iss 1000 :mss 1000)
  (let ((syn (mine (first syns))))
    (ok "the SYN carries our ISS and our MSS" (and (= (seg-seq syn) 1000) (= (seg-mss syn) 1000)
                                                   (= (seg-flags syn) +tcp-syn+))))
  (ok "a SYN-ACK that acks the wrong number is ignored"
      (and (null (tcp-input c (peer-seg 5000 999 (logior +tcp-syn+ +tcp-ack+) (v)) 10))
           (eq (tcp-conn-state c) :syn-sent)))
  (ok "the right SYN-ACK establishes"
      (equal (tcp-input c (peer-seg 5000 1001 (logior +tcp-syn+ +tcp-ack+) (v) :mss 500) 20) '(:established)))
  (let ((ack (mine (first (tcp-output c 20)))))
    (ok "and is acknowledged" (and (= (seg-seq ack) 1001) (= (seg-ack ack) 5001)
                                   (= (seg-flags ack) +tcp-ack+))))
  (tcp-write c (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 7))
  (let ((segs (mapcar #'mine (tcp-output c 30))))
    (ok "segments respect the peer's smaller MSS (500)"
        (equal (mapcar (lambda (s) (length (seg-data s))) segs) '(500 500 200)))))

(head "a lost SYN")
(multiple-value-bind (c syns) (tcp-open *us* *them* 40000 80 0 :iss 77)
  (declare (ignore syns))
  (ok "nothing is resent before the RTO" (null (tcp-output c 999)))
  (let ((again (mapcar #'mine (tcp-output c 1000))))
    (ok "the SYN is resent at 1 s" (and (= (length again) 1) (= (seg-seq (first again)) 77)
                                        (logtest (seg-flags (first again)) +tcp-syn+))))
  (ok "then at 2 s more (backoff)" (and (null (tcp-output c 2999)) (tcp-output c 3000))))

(head "data, in order and out of order")
(multiple-value-bind (c their ours) (open-conn)
  (ok "in-order data is delivered" (member :data (tcp-input c (peer-seg their ours +tcp-ack+ (ascii "hello ")) 100)))
  (ok "... and read" (equalp (tcp-read c) (ascii "hello ")))
  (let ((later (seq+ their 12)))
    (ok "data past a gap is held, not delivered"
        (and (null (member :data (tcp-input c (peer-seg later ours +tcp-ack+ (ascii "world")) 110)))
             (zerop (length (tcp-read c)))))
    (let ((ack (mine (first (tcp-output c 110)))))
      (ok "... and acks the gap's start (a duplicate ack)" (= (seg-ack ack) (seq+ their 6))))
    (ok "the gap filled delivers both, in order"
        (and (member :data (tcp-input c (peer-seg (seq+ their 6) ours +tcp-ack+ (ascii "there ")) 120))
             (equalp (tcp-read c) (ascii "there world")))))
  (ok "a duplicate of delivered data is not delivered again"
      (and (null (member :data (tcp-input c (peer-seg their ours +tcp-ack+ (ascii "hello ")) 130)))
           (zerop (length (tcp-read c)))))
  (ok "a segment overlapping delivered data gives only the new part"
      (progn (tcp-input c (peer-seg (seq+ their 15) ours +tcp-ack+ (ascii "ld!!")) 140)
             (equalp (tcp-read c) (ascii "!!")))))

(head "sending, acks and retransmission")
(multiple-value-bind (c their ours) (open-conn)
  (tcp-write c (ascii "GET / HTTP/1.0

"))
  (let ((s (mine (first (tcp-output c 0)))))
    (ok "our data goes out at our next sequence number" (and (= (seg-seq s) ours) (equalp (seg-data s) (ascii "GET / HTTP/1.0

")))))
  (ok "unacked, it is resent after 1 s" (= 1 (length (tcp-output c 1000))))
  (tcp-input c (peer-seg their (seq+ ours 16) +tcp-ack+ (v)) 1100)
  (ok "acked, it is forgotten" (and (null (tcp-conn-unacked c)) (null (tcp-output c 100000)))))
(multiple-value-bind (c their ours) (open-conn)
  (declare (ignore their ours))
  (tcp-write c (ascii "x"))
  (tcp-output c 0)
  (let ((events nil))
    (loop for now from 1000 by 1000 repeat 200
          do (multiple-value-bind (segs ev) (tcp-output c (* now 64)) (declare (ignore segs))
               (when ev (setf events ev) (return))))
    (ok "a peer that never acks ends in a reset, after the retries" (equal events '(:reset)))
    (ok "... and the connection is closed" (eq (tcp-conn-state c) :closed))))

(head "the window")
(multiple-value-bind (c their ours) (open-conn)
  (declare (ignore ours))
  (tcp-input c (peer-seg their (seq+ 1000 1) +tcp-ack+ (v) :window 1500) 0)
  (tcp-write c (make-array 5000 :element-type '(unsigned-byte 8) :initial-element 1))
  (ok "no more than the peer's window is in flight (1500)"
      (= 1500 (reduce #'+ (mapcar (lambda (s) (length (seg-data (mine s)))) (tcp-output c 0)))))
  (ok "nothing more until it opens" (null (tcp-output c 10))))

(head "closing")
(multiple-value-bind (c their ours) (open-conn)
  (ok "their FIN after data: data and eof"
      (equal (tcp-input c (peer-seg their ours (logior +tcp-ack+ +tcp-fin+) (ascii "bye")) 0) '(:data :eof)))
  (ok "the FIN takes its sequence number after the payload"
      (= (seg-ack (mine (first (tcp-output c 0)))) (seq+ their 4)))
  (tcp-close c)
  (let ((fin (mine (first (tcp-output c 10)))))
    (ok "our FIN goes out" (logtest (seg-flags fin) +tcp-fin+))
    (ok "acked, the connection is closed"
        (and (member :closed (tcp-input c (peer-seg (seq+ their 4) (seq+ (seg-seq fin) 1) +tcp-ack+ (v)) 20))
             (tcp-closed-p c)))))
(multiple-value-bind (c their ours) (open-conn)
  (tcp-input c (peer-seg (seq+ their 5) ours (logior +tcp-ack+ +tcp-fin+) (v)) 0)
  (ok "a FIN past a gap does not end the stream" (not (tcp-eof-p c)))
  (tcp-input c (peer-seg their ours +tcp-ack+ (ascii "12345")) 1)
  (ok "... until the gap fills" (and (tcp-eof-p c) (equalp (tcp-read c) (ascii "12345"))))
  (tcp-input c (peer-seg (seq+ their 5) ours (logior +tcp-ack+ +tcp-fin+) (v)) 2)
  (ok "(a retransmitted FIN after that is harmless)" (tcp-eof-p c)))

(head "reset")
(multiple-value-bind (c their ours) (open-conn)
  (ok "a reset far outside the window is ignored"
      (and (null (tcp-input c (peer-seg (seq+ their 900000) ours +tcp-rst+ (v)) 0))
           (eq (tcp-conn-state c) :established)))
  (ok "a reset at the expected sequence number closes"
      (and (equal (tcp-input c (peer-seg their ours +tcp-rst+ (v)) 0) '(:reset))
           (tcp-conn-reset c))))

(head "sequence numbers wrap at 2^32")
(multiple-value-bind (c their ours) (open-conn :iss #xfffffff0 :their-iss #xfffffffa)
  (tcp-write c (make-array 40 :element-type '(unsigned-byte 8) :initial-element 2))
  (let ((s (mine (first (tcp-output c 0)))))
    (ok "our data starts just below 2^32" (= (seg-seq s) #xfffffff1))
    (tcp-input c (peer-seg their (seq+ ours 40) +tcp-ack+ (ascii "0123456789")) 10)
    (ok "an ack past the wrap acknowledges it" (null (tcp-conn-unacked c)))
    (ok "their data across the wrap is delivered" (equalp (tcp-read c) (ascii "0123456789")))
    (ok "and acked at the wrapped number"
        (= (seg-ack (mine (first (tcp-output c 20)))) (seq+ #xfffffffa 11)))))

(format t "~%~d passed, ~d failed~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
