;;;; src/ice-loop.lisp -- the ICE agent on an event loop: no threads, no blocking reads.
;;;;
;;;; ice.lisp and turn.lisp were written for a thread per job: ICE-SERVE's receive thread, a
;;;; check thread, a thread per TURN ChannelBind (it waits on a condition variable the receive
;;;; thread signals, so it cannot be the receive thread), and blocking reads for STUN and TURN
;;;; gathering that had to finish before the receive thread took the socket.  On a board with
;;;; twelve thread slots that was most of a session's budget, and every one of them had to be
;;;; made to end.  Here the same agent runs on a CL-TRANSPORT.LOOP:EVENT-LOOP:
;;;;
;;;;   RECEIVE      a watch on the agent's UDP socket drains it into ICE-DISPATCH.
;;;;   TRANSACTIONS every STUN/TURN request is a TXN: sent, retransmitted on a timer (RFC 5389
;;;;                §7.2.1 backoff, same transaction id), and answered by its reply arriving
;;;;                through that same watch -- ICE-DISPATCH hands any datagram whose
;;;;                transaction id is pending here to %TXN-REPLY.  The caller gets a callback.
;;;;   GATHERING    srflx (STUN), relay (TURN Allocate, 401/438 dance) and the peer's
;;;;                permissions run at once; ON-DONE fires when all have answered or given up.
;;;;   CHECKS       a periodic timer, not a thread.
;;;;   REFRESH      a periodic TURN Refresh (the threaded path never refreshed at all).
;;;;   CLOSE        release the allocation, cancel the timers, unwatch, close.  Nothing to join.
;;;;
;;;; Every function here runs on the loop's thread.  The blocking API in ice.lisp is untouched,
;;;; for callers with threads to spend.

(in-package #:cl-transport.ice)

;;; ---- timers owned by an agent (all cancelled at close) -----------------------------------

(defun %agent-after (agent seconds fn what)
  (let ((tm (cl-transport.loop:after (ice-agent-loop agent) seconds fn :what what)))
    (push tm (ice-agent-timers agent))
    tm))

(defun %agent-every (agent seconds fn what)
  (let ((tm (cl-transport.loop:every-seconds (ice-agent-loop agent) seconds fn :what what)))
    (push tm (ice-agent-timers agent))
    tm))

(defun %agent-cancel (agent tm)
  (when tm
    (cl-transport.loop:cancel (ice-agent-loop agent) tm)
    (setf (ice-agent-timers agent) (delete tm (ice-agent-timers agent)))))

;;; ---- transactions ------------------------------------------------------------------------

(defclass txn ()
  ((tid :initarg :tid :reader txn-tid)
   (want :initarg :want :reader txn-want)            ; the reply types that answer it
   (on-done :initarg :on-done :reader txn-on-done)   ; (lambda (type attrs)) -- NIL NIL on timeout
   (timer :initform nil :accessor txn-timer)))

(defun %txn-start (agent msg tid host port want on-done &key (timeout 2.0) (what "stun txn"))
  "Send MSG (transaction TID) to HOST:PORT, retransmitting the same bytes on a 0.5 s doubling
to 2 s backoff until a reply of a type in WANT arrives or TIMEOUT passes.  ON-DONE is called
once, with the reply's type and attributes, or NIL NIL on timeout."
  (let* ((txn (make-instance 'txn :tid tid :want want :on-done on-done))
         (deadline (+ (cl-transport.loop:now-seconds) timeout))
         (rto 0.5))
    (setf (gethash tid (ice-agent-txns agent)) txn)
    (labels ((send () (ignore-errors (ice-send agent msg host port)))
             (tick ()
               (setf (txn-timer txn) nil)
               (when (eq (gethash tid (ice-agent-txns agent)) txn)
                 (let ((left (- deadline (cl-transport.loop:now-seconds))))
                   (cond ((<= left 0)
                          (remhash tid (ice-agent-txns agent))
                          (funcall on-done nil nil))
                         (t (send)
                            (setf rto (min 2.0 (* rto 2)))
                            (setf (txn-timer txn) (%agent-after agent (min rto left) #'tick what))))))))
      (send)
      (setf (txn-timer txn) (%agent-after agent (min rto timeout) #'tick what)))
    txn))

(defun %txn-reply (agent pkt)
  "PKT is a STUN message.  If it answers one of AGENT's pending transactions, complete that
transaction and return T; otherwise NIL (it is the peer's, or a stray)."
  (multiple-value-bind (type tid attrs) (ignore-errors (decode-stun pkt))
    (let ((txn (and tid (gethash tid (ice-agent-txns agent)))))
      (when txn
        (when (member type (txn-want txn))
          (remhash tid (ice-agent-txns agent))
          (%agent-cancel agent (txn-timer txn))
          (funcall (txn-on-done txn) type attrs))
        t))))

;;; ---- TURN requests -----------------------------------------------------------------------

(defun %turn-request-async (agent alloc type extra on-done &key want-success (timeout 2.0) authed)
  "A TURN request as a transaction to the server.  ON-DONE gets (type attrs), NIL NIL on timeout."
  (let* ((tid (stun-transaction-id))
         (attrs (if authed (%turn-auth-attrs alloc extra) extra))
         (msg (encode-stun type tid attrs :integrity-key (and authed (turn-alloc-key alloc)))))
    (%txn-start agent msg tid (turn-alloc-server-host alloc) (turn-alloc-server-port alloc)
                (list want-success (logior type #x0110)) on-done
                :timeout timeout :what "turn txn")))

(defun %turn-authed-async (agent alloc type extra want-success on-done &key (timeout 2.0))
  "An authenticated TURN request that adopts a fresh NONCE and retries once on 438 (stale nonce).
ON-DONE gets (type attrs)."
  (%turn-request-async
   agent alloc type extra
   (lambda (rtype rattrs)
     (if (and rtype (eql (%parse-error-code rattrs) 438))
         (let ((n (stun-attr rattrs +attr-nonce+)))
           (when n (setf (turn-alloc-nonce alloc) n))
           (%turn-request-async agent alloc type extra on-done
                                :want-success want-success :timeout timeout :authed t))
         (funcall on-done rtype rattrs)))
   :want-success want-success :timeout timeout :authed t))

(defun turn-allocate-async (agent alloc on-done &key (timeout 2.0))
  "TURN-ALLOCATE as transactions: unauthenticated Allocate -> 401 (REALM, NONCE) -> the
authenticated one (a 438 adopts the new nonce and retries).  ON-DONE gets T or NIL."
  (let ((req (as-u8vec '(17 0 0 0))))                 ; REQUESTED-TRANSPORT: UDP
    (%turn-request-async
     agent alloc +turn-allocate+
     (list (cons +attr-requested-transport+ req) (cons +attr-software+ (ascii "webrtc-data")))
     (lambda (rtype rattrs)
       (cond
         ((null rtype) (funcall on-done nil))
         ((eql rtype +turn-allocate-success+)        ; an open relay: no auth asked for
          (funcall on-done (%ingest-allocate-success alloc rattrs)))
         (t
          (let ((realm (stun-attr rattrs +attr-realm+)) (nonce (stun-attr rattrs +attr-nonce+)))
            (if (not (and realm nonce))
                (funcall on-done nil)
                (progn
                  (setf (turn-alloc-realm alloc) (bytes->ascii realm)
                        (turn-alloc-nonce alloc) nonce
                        (turn-alloc-key alloc) (turn-long-term-key (turn-alloc-user alloc)
                                                                   (turn-alloc-realm alloc)
                                                                   (turn-alloc-pass alloc)))
                  (%turn-authed-async
                   agent alloc +turn-allocate+ (list (cons +attr-requested-transport+ req))
                   +turn-allocate-success+
                   (lambda (rt ra)
                     (funcall on-done (and (eql rt +turn-allocate-success+)
                                           (%ingest-allocate-success alloc ra))))
                   :timeout timeout)))))))
     :want-success +turn-allocate-success+ :timeout timeout)))

(defun turn-create-permission-async (agent alloc peer-ip on-done &key (timeout 2.0))
  "CreatePermission for PEER-IP (dotted).  ON-DONE gets T or NIL.  Already-permitted is T at once."
  (if (gethash peer-ip (turn-alloc-perms alloc))
      (funcall on-done t)
      (%turn-authed-async
       agent alloc +turn-create-perm+
       (list (cons +attr-xor-peer-address+ (xor-mapped-address (%inet peer-ip) 0)))
       +turn-create-perm-success+
       (lambda (rtype rattrs)
         (declare (ignore rattrs))
         (let ((ok (eql rtype +turn-create-perm-success+)))
           (when ok (setf (gethash peer-ip (turn-alloc-perms alloc)) t))
           (funcall on-done ok)))
       :timeout timeout)))

(defun %bind-relay-peer-on-loop (agent alloc from-host from-port)
  "ICE-BIND-RELAY-PEER-ASYNC's work as transactions: CreatePermission then ChannelBind, so
traffic from that peer upgrades from Data indications to ChannelData."
  (let* ((ip (format nil "~{~d~^.~}" (coerce from-host 'list)))
         (k (format nil "~a:~d" ip from-port)))
    (when (and (not (gethash k (turn-alloc-peer->chan alloc)))
               (not (gethash k (turn-alloc-binding alloc))))
      (setf (gethash k (turn-alloc-binding alloc)) t)
      (let ((chan (let ((c (turn-alloc-next-channel alloc)))
                    (setf (turn-alloc-next-channel alloc) (1+ c)) c)))
        (turn-create-permission-async
         agent alloc ip
         (lambda (ok)
           (declare (ignore ok))                     ; a ChannelBind installs one anyway
           (%turn-authed-async
            agent alloc +turn-channel-bind+
            (list (cons +attr-channel-number+ (cat-bytes (u16be chan) (u16be 0)))
                  (cons +attr-xor-peer-address+ (xor-mapped-address from-host from-port)))
            +turn-channel-bind-success+
            (lambda (rtype rattrs)
              (declare (ignore rattrs))
              (remhash k (turn-alloc-binding alloc))
              (when (eql rtype +turn-channel-bind-success+)
                (setf (gethash k (turn-alloc-peer->chan alloc)) chan
                      (gethash chan (turn-alloc-chan->peer alloc)) (cons ip from-port)
                      (gethash ip (turn-alloc-perms alloc)) t))))))))))

(defun %turn-refresh-on-loop (agent alloc &key (lifetime nil))
  (%turn-authed-async agent alloc +turn-refresh+
                      (list (cons +attr-lifetime+ (u32be (or lifetime (turn-alloc-lifetime alloc)))))
                      +turn-refresh-success+
                      (lambda (rtype rattrs)
                        (declare (ignore rattrs))
                        (unless (eql rtype +turn-refresh-success+)
                          (format t "~&@@ turn refresh FAILED~%") (finish-output)))))

;;; ---- name resolution, once ----------------------------------------------------------------
;;; Resolving a name is a blocking DNS round trip, and the loop must not wait on one per offer
;;; for the same two servers.  Remembered for the life of the process; a dotted string is free.

(defvar *resolved* (make-hash-table :test 'equal))
(defun %resolve-once (host)
  (or (gethash host *resolved*)
      (let ((ip (resolve-host host)))
        (when ip (setf (gethash host *resolved*) ip))
        ip)))

;;; ---- gathering ----------------------------------------------------------------------------

(defun %gather-srflx-async (agent on-done &key (timeout 1.5))
  "Binding request to each of *STUN-SERVERS* in turn until one answers; sets SRFLX-IP/PORT.
ON-DONE gets T or NIL."
  (labels ((try (servers)
             (if (null servers)
                 (funcall on-done nil)
                 (let ((ip (%resolve-once (car (first servers)))))
                   (if (null ip)
                       (try (rest servers))
                       (let ((tid (stun-transaction-id)))
                         (%txn-start agent (encode-stun +binding-request+ tid nil :fingerprint t) tid
                                     (sb-bsd-sockets:make-inet-address ip) (cdr (first servers))
                                     (list +binding-success+)
                                     (lambda (type attrs)
                                       (multiple-value-bind (mip mport)
                                           (and type (parse-xor-mapped-address
                                                      (stun-attr attrs +attr-xor-mapped-address+)))
                                         (if mip
                                             (progn (setf (ice-agent-srflx-ip agent) mip
                                                          (ice-agent-srflx-port agent) mport)
                                                    (funcall on-done t))
                                             (try (rest servers)))))
                                     :timeout timeout :what "stun srflx")))))))
    (try *stun-servers*)))

(defun %gather-relay-async (agent on-done &key server user pass (timeout 2.0) (use-mapped-srflx t))
  "ICE-GATHER-RELAY as transactions: Allocate, then one CreatePermission per unique IPv4 address
the peer offered, all at once.  ON-DONE gets T once every permission has answered (each says
ok/FAILED), NIL if there is no relay."
  (let* ((srv (or server (uiop:getenv "TURN_SERVER")))
         (usr (or user (uiop:getenv "TURN_USER")))
         (pw (or pass (uiop:getenv "TURN_PASS")))
         (colon (and srv (position #\: srv)))
         (ip (and colon usr pw (%resolve-once (subseq srv 0 colon)))))
    (if (null ip)
        (funcall on-done nil)
        (let ((alloc (make-turn-alloc :socket (ice-agent-socket agent)
                                      :server-host (sb-bsd-sockets:make-inet-address ip)
                                      :server-port (parse-integer (subseq srv (1+ colon)))
                                      :user usr :pass pw)))
          ;; the agent knows its server from the first request: replies route by transaction id,
          ;; but relayed peer data is recognised by its SOURCE, so ICE-DISPATCH must know it now
          (setf (ice-agent-turn agent) alloc)
          (turn-allocate-async
           agent alloc
           (lambda (ok)
             (if (not ok)
                 (progn (setf (ice-agent-turn agent) nil) (funcall on-done nil))
                 (progn
                   (setf (ice-agent-relay-ip agent) (turn-alloc-relay-ip alloc)
                         (ice-agent-relay-port agent) (turn-alloc-relay-port alloc))
                   (when (and use-mapped-srflx (turn-alloc-mapped-ip alloc)
                              (not (ice-agent-srflx-ip agent)))
                     (setf (ice-agent-srflx-ip agent) (turn-alloc-mapped-ip alloc)
                           (ice-agent-srflx-port agent) (turn-alloc-mapped-port alloc)))
                   ;; keep the allocation alive for as long as the session lasts
                   (%agent-every agent (max 30 (floor (turn-alloc-lifetime alloc) 2))
                                 (lambda () (%turn-refresh-on-loop agent alloc)) "turn refresh")
                   (let* ((ips (remove-duplicates
                                (remove-if-not #'%ipv4-literal-p
                                               (mapcar #'ice-candidate-ip (ice-agent-remote-candidates agent)))
                                :test #'equal))
                          (proxy (uiop:getenv "TURN_RELAY_PEER"))
                          (ips (if (and proxy (plusp (length proxy))) (adjoin proxy ips :test #'equal) ips))
                          (left (length ips)))
                     (if (zerop left)
                         (funcall on-done t)
                         (dolist (pip ips)
                           (let ((pip pip))
                             (turn-create-permission-async
                              agent alloc pip
                              (lambda (pok)
                                (format t "~&@@ turn permission ~a: ~a~%" pip (if pok "ok" "FAILED"))
                                (finish-output)
                                (when (zerop (decf left)) (funcall on-done t)))))))))))
           :timeout timeout)))))

;;; ---- the agent on a loop ------------------------------------------------------------------

(defun %ice-drain (agent buf)
  "Read every datagram waiting on the agent's socket (bounded, so one busy peer cannot starve
the rest of the loop) and dispatch each."
  (let ((sock (ice-agent-socket agent)) (fd nil))
    (setq fd (ignore-errors (sb-bsd-sockets:socket-file-descriptor sock)))
    (loop repeat 64
          while (and fd (not (ice-agent-stop agent))
                     (ignore-errors (sb-sys:wait-until-fd-usable fd :input 0)))
          do (multiple-value-bind (b len host port)
                 (handler-case (sb-bsd-sockets:socket-receive sock buf nil)
                   (error () (values nil nil nil nil)))
               (declare (ignore b))
               (if (and len (plusp len))
                   (ice-dispatch agent buf len host port)
                   (return))))))

(defun ice-start-on-loop (agent loop &key gather-srflx gather-relay on-gathered)
  "Run AGENT on LOOP: watch its socket, then gather (srflx with GATHER-SRFLX, a TURN relay with
GATHER-RELAY -- T for the environment's server, or a plist :server/:user/:pass) concurrently.
ON-GATHERED is called with AGENT when gathering has finished, which is when the answer can be
built.  Returns AGENT.  Call ICE-START-CHECKS-ON-LOOP once the answer is out."
  (setf (ice-agent-loop agent) loop)
  (let ((buf (make-array 4096 :element-type '(unsigned-byte 8))))
    (cl-transport.loop:watch loop (ice-agent-socket agent)
                             (lambda (sock) (declare (ignore sock)) (%ice-drain agent buf))
                             :what "ice receive"))
  (let ((left 1) (fired nil))
    (flet ((one-done (&rest ignore)
             (declare (ignore ignore))
             (when (and (zerop (decf left)) (not fired))
               (setq fired t)
               (when on-gathered (funcall on-gathered agent)))))
      (when gather-srflx (incf left) (%gather-srflx-async agent #'one-done))
      (when gather-relay
        (incf left)
        (apply #'%gather-relay-async agent #'one-done (if (listp gather-relay) gather-relay '())))
      (one-done)))
  agent)

(defun ice-start-checks-on-loop (agent &key (interval 0.2) (duration 15.0) (priority 1845494015))
  "ICE-START-CHECKS on a timer: STUN checks to each IPv4 candidate every INTERVAL until a peer is
selected, the agent stops, or DURATION passes.  They punch our NAT open toward the peer."
  (let ((deadline (+ (cl-transport.loop:now-seconds) duration))
        (tiebreaker (random-bytes 8))
        (username (ascii (format nil "~a:~a" (ice-agent-remote-ufrag agent) (ice-agent-local-ufrag agent))))
        (targets (remove-if-not #'%ipv4-literal-p (ice-agent-remote-candidates agent) :key #'ice-candidate-ip))
        (tm nil))
    (flet ((round-of-checks ()
             (if (or (ice-agent-peer agent) (ice-agent-stop agent)
                     (>= (cl-transport.loop:now-seconds) deadline))
                 (%agent-cancel agent tm)
                 (dolist (c targets)
                   (ignore-errors
                    (ice-send agent
                              (encode-stun +binding-request+ (stun-transaction-id)
                                           (list (cons +attr-username+ username)
                                                 (cons +attr-ice-controlled+ tiebreaker)
                                                 (cons +attr-priority+ (u32be priority)))
                                           :integrity-key (ice-agent-remote-pwd agent) :fingerprint t)
                              (sb-bsd-sockets:make-inet-address (ice-candidate-ip c))
                              (ice-candidate-port c)))))))
      (round-of-checks)
      (setq tm (%agent-every agent interval #'round-of-checks "ice checks"))))
  agent)

(defun ice-close-on-loop (agent)
  "End AGENT on its loop: release the TURN allocation (one Refresh with lifetime 0, not waited
for), cancel every timer and transaction, unwatch and close the socket."
  (unless (ice-agent-stop agent)
    (let ((alloc (ice-agent-turn agent)))
      (when (and alloc (turn-alloc-key alloc))
        (ignore-errors
         (%send-to-server alloc (encode-stun +turn-refresh+ (stun-transaction-id)
                                             (%turn-auth-attrs alloc (list (cons +attr-lifetime+ (u32be 0))))
                                             :integrity-key (turn-alloc-key alloc))))))
    (setf (ice-agent-stop agent) t)
    (let ((loop (ice-agent-loop agent)))
      (dolist (tm (ice-agent-timers agent)) (cl-transport.loop:cancel loop tm))
      (setf (ice-agent-timers agent) '())
      (clrhash (ice-agent-txns agent))
      (cl-transport.loop:unwatch loop (ice-agent-socket agent)))
    (ignore-errors (sb-bsd-sockets:socket-close (ice-agent-socket agent))))
  nil)
