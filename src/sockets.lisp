;;;; src/sockets.lisp -- portable UDP and TCP on sb-bsd-sockets: SBCL and modus.
;;;;
;;;; Written against SBCL's own sb-bsd-sockets and SB-SYS:WAIT-UNTIL-FD-USABLE --
;;;; no usocket -- because modus provides exactly that API (its net/sb-sys-shim),
;;;; so the same code serves a program on SBCL and on hosted modus.  No threads:
;;;; everything here either returns at once or waits with a timeout the caller
;;;; gives, so it fits an event loop and modus's actors.
;;;;
;;;; UDP: one socket, many peers.  A UDP-ENDPOINT sorts arriving datagrams by
;;;; source address into per-peer queues; a peer's handle reads from its own queue
;;;; (pumping the socket when it is empty, queueing what arrives for the others).
;;;; A datagram from an address with no handle is kept only if the endpoint's
;;;; ADMIT predicate wants it -- e.g. a protocol's handshake opener -- and
;;;; UDP-ACCEPT hands it out with a handle for its sender.
;;;;
;;;; TCP: a TCP-SOCKET keeps its OWN receive buffer rather than a Lisp stream's, so
;;;; "is there input?" has one answer -- bytes buffered, or the descriptor
;;;; readable -- and an event loop never waits on a descriptor while bytes sit
;;;; unseen above it.  TCP-READ-EXACTLY's deadline covers the whole request.
;;;;
;;;; WAIT-READABLE waits on any mix of TCP sockets, listeners and one UDP
;;;; endpoint.  There is no portable multi-descriptor wait, so it checks each
;;;; descriptor and sleeps in slices of 10 ms on one of them: a TCP readiness is
;;;; seen at most that late, a UDP one at once.

(defpackage #:cl-transport.sockets
  (:use #:cl)
  (:export
   ;; addresses
   #:dotted-quad #:resolve-host
   ;; UDP
   #:udp-endpoint #:udp-endpoint-p #:udp-open #:udp-close #:udp-closed-p #:udp-local-port
   #:udp-endpoint-received #:udp-endpoint-dropped #:udp-endpoint-peer-count #:udp-endpoint-strangers
   #:udp-pump #:udp-send
   #:udp-peer #:udp-peer-p #:udp-peer-handle #:udp-peer-host #:udp-peer-port #:udp-peer-ready-p
   #:udp-peer-read #:udp-peer-write #:udp-peer-close
   #:udp-accept #:udp-accept-pending-p #:udp-offer
   ;; TCP
   #:tcp-socket #:tcp-socket-p #:tcp-connect #:tcp-listen #:tcp-listener-port #:tcp-accept
   #:tcp-listener-close #:tcp-read-exactly #:tcp-read-available #:tcp-buffered-p
   #:tcp-write #:tcp-shutdown-output #:tcp-close #:tcp-closed-p
   ;; waiting
   #:wait-readable #:seconds-until))

(in-package #:cl-transport.sockets)

(defun seconds-until (deadline)
  "Seconds from now until DEADLINE (an absolute GET-INTERNAL-REAL-TIME), or NIL."
  (and deadline (/ (float (- deadline (get-internal-real-time)) 1d0) internal-time-units-per-second)))

(defun %octets (n) (make-array n :element-type '(unsigned-byte 8)))
(defun %simple (v) (coerce v '(simple-array (unsigned-byte 8) (*))))

;;; --- addresses -------------------------------------------------------------------

(defun dotted-quad (host)
  "#(a b c d) for a dotted-quad string, else NIL."
  (let ((parts '()) (start 0))
    (loop for dot = (position #\. host :start start)
          do (push (subseq host start dot) parts)
             (if dot (setf start (1+ dot)) (return)))
    (when (= (length parts) 4)
      (let ((nums (mapcar (lambda (p) (ignore-errors (parse-integer p))) (nreverse parts))))
        (when (every (lambda (n) (and n (<= 0 n 255))) nums)
          (coerce nums 'vector))))))

(defun resolve-host (host)
  "HOST -- a dotted quad, a name, or a 4-element vector -- as a 4-element vector.
   A string is checked first: on modus a string also satisfies (VECTOR (UNSIGNED-BYTE 8))."
  (cond ((stringp host)
         (or (dotted-quad host)
             (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host))))
        ((vectorp host) host)
        (t (error "not a host: ~s" host))))

(defun %fd-of (s)
  (sb-bsd-sockets:socket-file-descriptor
   (cond ((tcp-socket-p s) (tcp-socket-sock s))
         ((udp-endpoint-p s) (udp-endpoint-socket s))
         (t s))))

(defun %readable-p (s seconds)
  (ignore-errors (sb-sys:wait-until-fd-usable (%fd-of s) :input (max 0 seconds))))

;;; --- UDP ---------------------------------------------------------------------------

(defstruct (udp-endpoint (:constructor %make-udp-endpoint (socket admit max-queue max-strangers)))
  socket admit max-queue max-strangers
  (peers (make-hash-table :test 'equal))   ; (host-octets port) -> UDP-PEER
  (strangers '())                          ; ((key . datagram) ...), newest first
  (received 0) (dropped 0) (closed nil))

(defstruct (udp-peer (:constructor %make-udp-peer (endpoint key host port)))
  endpoint key host port (queue '()) (tail '())
  (handle-port nil))                       ; whatever the caller wrapped it in

(defun udp-open (&key (host "127.0.0.1") (port 0) (admit (constantly nil))
                   (max-queue 256) (max-strangers 64))
  "A UDP endpoint bound to HOST:PORT (loopback, ephemeral by default).  ADMIT is
   called with a datagram from an address that has no peer handle; true keeps it
   for UDP-ACCEPT (at most MAX-STRANGERS, the oldest dropped).  MAX-QUEUE bounds
   each peer's queue."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (handler-case (sb-bsd-sockets:socket-bind s (resolve-host host) port)
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close s)) (error e)))
    (%make-udp-endpoint s admit max-queue max-strangers)))

(defun udp-local-port (ep) (nth-value 1 (sb-bsd-sockets:socket-name (udp-endpoint-socket ep))))
(defun udp-closed-p (ep) (udp-endpoint-closed ep))
(defun udp-endpoint-peer-count (ep) (hash-table-count (udp-endpoint-peers ep)))

(defun udp-close (ep)
  (unless (udp-endpoint-closed ep)
    (setf (udp-endpoint-closed ep) t)
    (ignore-errors (sb-bsd-sockets:socket-close (udp-endpoint-socket ep)))))

(defun %key (host port) (list (coerce (resolve-host host) 'list) port))

(defun %enqueue (peer datagram)
  (let ((cell (list datagram)))
    (if (udp-peer-queue peer)
        (setf (cdr (udp-peer-tail peer)) cell)
        (setf (udp-peer-queue peer) cell))
    (setf (udp-peer-tail peer) cell)
    (when (> (length (udp-peer-queue peer)) (udp-endpoint-max-queue (udp-peer-endpoint peer)))
      (pop (udp-peer-queue peer)))))

(defun %dequeue (peer)
  (prog1 (pop (udp-peer-queue peer))
    (unless (udp-peer-queue peer) (setf (udp-peer-tail peer) nil))))

(defun %receive-one (ep)
  "Read one waiting datagram and file it.  T if one was read."
  (let ((buf (%octets 65536)))
    (multiple-value-bind (b size host port)
        (handler-case (sb-bsd-sockets:socket-receive (udp-endpoint-socket ep) buf (length buf))
          (error () (values nil nil nil nil)))
      (declare (ignore b))
      (when (and size host)
        (incf (udp-endpoint-received ep))
        (let* ((datagram (%simple (subseq buf 0 size)))
               (key (list (coerce host 'list) port))
               (peer (gethash key (udp-endpoint-peers ep))))
          (cond
            (peer (%enqueue peer datagram))
            ((and (funcall (udp-endpoint-admit ep) datagram)
                  (not (assoc key (udp-endpoint-strangers ep) :test #'equal)))
             (push (cons key datagram) (udp-endpoint-strangers ep))
             (when (> (length (udp-endpoint-strangers ep)) (udp-endpoint-max-strangers ep))
               (setf (udp-endpoint-strangers ep)
                     (subseq (udp-endpoint-strangers ep) 0 (udp-endpoint-max-strangers ep)))))
            (t (incf (udp-endpoint-dropped ep)))))
        t))))

(defun udp-pump (ep &key (timeout-ms 0))
  "Wait up to TIMEOUT-MS for input, then read every datagram already waiting.
   Returns the number read."
  (if (udp-endpoint-closed ep)
      0
      (let ((n 0))
        (when (%readable-p ep (/ (max 0 timeout-ms) 1000))
          (loop while (and (%receive-one ep) (progn (incf n) t) (%readable-p ep 0))))
        n)))

(defun udp-send (ep host port octets)
  "Send OCTETS as one datagram to HOST:PORT.  :OK or :CLOSED."
  (handler-case
      (progn (sb-bsd-sockets:socket-send (udp-endpoint-socket ep) octets (length octets)
                                         :address (list (resolve-host host) port))
             :ok)
    (error () :closed)))

(defun udp-peer-handle (ep host port)
  "A handle for datagrams to and from HOST:PORT through EP.  Signals if one is open."
  (let ((key (%key host port)))
    (when (gethash key (udp-endpoint-peers ep))
      (error "a handle for ~a:~d is already open" host port))
    ;; a datagram this address sent before the handle existed is not the handle's
    (setf (udp-endpoint-strangers ep) (remove key (udp-endpoint-strangers ep) :key #'car :test #'equal))
    (setf (gethash key (udp-endpoint-peers ep))
          (%make-udp-peer ep key (first key) port))))

(defun udp-peer-ready-p (peer) (and (udp-peer-queue peer) t))

(defun udp-peer-read (peer deadline)
  "The next datagram from PEER, waiting until DEADLINE (an absolute
   GET-INTERNAL-REAL-TIME, or NIL for no limit).  (values octets status), STATUS
   :ok, :timeout or :eof (the endpoint closed)."
  (let ((ep (udp-peer-endpoint peer)))
    (loop
      (cond ((udp-endpoint-closed ep) (return (values (%octets 0) :eof)))
            ((udp-peer-queue peer) (return (values (%dequeue peer) :ok))))
      (let ((wait (seconds-until deadline)))
        (when (and wait (<= wait 0)) (return (values (%octets 0) :timeout)))
        (udp-pump ep :timeout-ms (if wait (ceiling (* 1000 wait)) 1000))))))

(defun udp-peer-write (peer octets)
  "Send OCTETS to PEER as one datagram.  :OK or :CLOSED."
  (udp-send (udp-peer-endpoint peer) (coerce (udp-peer-host peer) 'vector) (udp-peer-port peer) octets))

(defun udp-peer-close (peer)
  "Forget PEER (the endpoint stays open for the others)."
  (remhash (udp-peer-key peer) (udp-endpoint-peers (udp-peer-endpoint peer))))

(defun udp-accept (ep &key (timeout-ms 0))
  "The oldest admitted stranger's datagram, with a handle for its sender holding
   it queued.  (values peer host port), or NIL if none arrives in TIMEOUT-MS."
  (when (null (udp-endpoint-strangers ep)) (udp-pump ep :timeout-ms timeout-ms))
  (let ((entry (car (last (udp-endpoint-strangers ep)))))
    (when entry
      (setf (udp-endpoint-strangers ep) (butlast (udp-endpoint-strangers ep)))
      (destructuring-bind ((host port) . datagram) entry
        (let ((peer (%make-udp-peer ep (car entry) host port)))
          (setf (gethash (car entry) (udp-endpoint-peers ep)) peer)
          (%enqueue peer datagram)
          (values peer (format nil "~{~d~^.~}" host) port))))))

(defun udp-accept-pending-p (ep) (and (udp-endpoint-strangers ep) t))

(defun udp-offer (ep host port datagram)
  "Put DATAGRAM, from HOST:PORT, where UDP-ACCEPT will find it, as if a stranger
   had just sent it (when nothing is open or waiting for that address)."
  (let ((key (%key host port)))
    (unless (or (gethash key (udp-endpoint-peers ep))
                (assoc key (udp-endpoint-strangers ep) :test #'equal))
      (push (cons key datagram) (udp-endpoint-strangers ep)))))

;;; --- TCP ---------------------------------------------------------------------------

(defconstant +tcp-recv-chunk+ 65536)

(defstruct (tcp-socket (:constructor %make-tcp-socket (sock)))
  sock (buf (%octets 0)) (pos 0) (eof nil) (closed nil))

(defun tcp-closed-p (ts) (tcp-socket-closed ts))
(defun %buffered (ts) (- (length (tcp-socket-buf ts)) (tcp-socket-pos ts)))
(defun tcp-buffered-p (ts) (and (tcp-socket-p ts) (plusp (%buffered ts))))

(defun %fill (ts seconds)
  "Wait up to SECONDS for input and read what is there.  NIL if nothing came; end
   of stream sets EOF."
  (when (and (not (tcp-socket-eof ts)) (%readable-p ts seconds))
    (multiple-value-bind (buf n)
        ;; an explicit octet buffer: given NIL, SBCL allocates a CHARACTER one
        (handler-case (sb-bsd-sockets:socket-receive (tcp-socket-sock ts) (%octets +tcp-recv-chunk+)
                                                     +tcp-recv-chunk+)
          (error () (values nil 0)))
      (if (or (null n) (zerop n))
          (setf (tcp-socket-eof ts) t)
          (setf (tcp-socket-buf ts)
                (concatenate '(vector (unsigned-byte 8))
                             (subseq (tcp-socket-buf ts) (tcp-socket-pos ts)) (subseq buf 0 n))
                (tcp-socket-pos ts) 0))
      t)))

(defun %take (ts n)
  (prog1 (%simple (subseq (tcp-socket-buf ts) (tcp-socket-pos ts) (+ (tcp-socket-pos ts) n)))
    (incf (tcp-socket-pos ts) n)))

(defun tcp-read-exactly (ts n deadline)
  "Exactly N bytes from TS, by DEADLINE (absolute GET-INTERNAL-REAL-TIME, or NIL):
   the deadline covers the whole request, not each byte.  (values octets status),
   STATUS :ok, or :eof / :timeout with the bytes that did arrive."
  (loop
    (when (>= (%buffered ts) n) (return (values (%take ts n) :ok)))
    (when (tcp-socket-eof ts) (return (values (%take ts (%buffered ts)) :eof)))
    (let ((wait (seconds-until deadline)))
      (when (and wait (<= wait 0)) (return (values (%take ts (%buffered ts)) :timeout)))
      (unless (%fill ts (or wait 3600))
        (when wait (return (values (%take ts (%buffered ts)) :timeout)))))))

(defun tcp-read-available (ts)
  "Whatever bytes TS has now, without waiting.  (values octets eof-p)."
  (when (zerop (%buffered ts)) (%fill ts 0))
  (values (%take ts (%buffered ts)) (and (tcp-socket-eof ts) (zerop (%buffered ts)))))

(defun tcp-write (ts octets)
  "Write all of OCTETS.  :OK or :CLOSED."
  (handler-case
      (let ((v (%simple octets)) (sent 0))
        (loop while (< sent (length v))
              do (let ((n (sb-bsd-sockets:socket-send (tcp-socket-sock ts) (subseq v sent) (- (length v) sent))))
                   (when (or (null n) (<= n 0)) (return-from tcp-write :closed))
                   (incf sent n)))
        :ok)
    (error () :closed)))

(defun tcp-shutdown-output (ts)
  "Half-close: the peer reads end of stream; we can still read."
  (ignore-errors (sb-bsd-sockets:socket-shutdown (tcp-socket-sock ts) :direction :output)))

(defun tcp-close (ts)
  (unless (tcp-socket-closed ts)
    (setf (tcp-socket-closed ts) t)
    (ignore-errors (sb-bsd-sockets:socket-close (tcp-socket-sock ts)))))

(defun tcp-connect (host port &key (timeout-secs 10))
  "A TCP-SOCKET connected to HOST:PORT.  TIMEOUT-SECS bounds the connect on SBCL (a
   non-blocking connect); modus's sb-bsd-sockets has no non-blocking connect, so
   there it is the kernel's."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (addr (resolve-host host)))
    (handler-case
        (progn
          #+sbcl
          (progn
            (setf (sb-bsd-sockets:non-blocking-mode s) t)
            (handler-case (sb-bsd-sockets:socket-connect s addr port)
              (sb-bsd-sockets:operation-in-progress () nil))
            (unless (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor s) :output timeout-secs)
              (error "connect to ~a:~d timed out" host port))
            ;; the connect's outcome: a refused one shows as an error on the peer name
            (sb-bsd-sockets:socket-peername s)
            (setf (sb-bsd-sockets:non-blocking-mode s) nil))
          #-sbcl
          (progn timeout-secs (sb-bsd-sockets:socket-connect s addr port))
          (ignore-errors (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t))
          (%make-tcp-socket s))
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close s)) (error e)))))

(defun tcp-listen (&key (host "127.0.0.1") (port 0) (backlog 16))
  "A listening socket on HOST (loopback by default) and PORT (0 = ephemeral)."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
          (sb-bsd-sockets:socket-bind s (resolve-host host) port)
          (sb-bsd-sockets:socket-listen s backlog)
          s)
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close s)) (error e)))))

(defun tcp-listener-port (listener) (nth-value 1 (sb-bsd-sockets:socket-name listener)))
(defun tcp-listener-close (listener) (ignore-errors (sb-bsd-sockets:socket-close listener)))

(defun tcp-accept (listener &key timeout-ms)
  "The next connection as a TCP-SOCKET, or NIL if TIMEOUT-MS passes first (or the
   accept fails: out of descriptors, or the connection went away first)."
  (when (%readable-p listener (if timeout-ms (/ timeout-ms 1000) 3600))
    (let ((s (handler-case (sb-bsd-sockets:socket-accept listener) (error () nil))))
      (when s
        (ignore-errors (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t))
        (%make-tcp-socket s)))))

;;; --- waiting -------------------------------------------------------------------------

(defun wait-readable (sockets timeout-ms &key udp)
  "The members of SOCKETS (TCP-SOCKETs and listeners) readable within TIMEOUT-MS --
   bytes already buffered count.  UDP, an endpoint, ends the wait too when it has
   input (it is pumped).  Checks every descriptor, then sleeps in slices of 10 ms
   on UDP if given, else on the first socket."
  (let ((deadline (+ (get-internal-real-time) (round (* timeout-ms internal-time-units-per-second) 1000))))
    (loop
      (let ((ready (remove-if-not (lambda (s) (or (tcp-buffered-p s) (%readable-p s 0))) sockets)))
        (when (or ready (and udp (plusp (udp-pump udp :timeout-ms 0))))
          (return ready))
        (let ((left (- deadline (get-internal-real-time))))
          (when (<= left 0) (return nil))
          (let ((slice (min 1/100 (/ left internal-time-units-per-second))))
            (cond (udp (udp-pump udp :timeout-ms (round (* slice 1000))))
                  (sockets (%readable-p (first sockets) slice))
                  (t (sleep slice)))))))))
