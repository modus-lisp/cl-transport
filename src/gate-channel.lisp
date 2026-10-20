;;;; gate-channel.lisp — the gate's bookkeeping, across threads that share no state.
;;;;
;;;; The gate keeps three things every caller writes to: the connection record, the
;;;; names learned from the resolver, and the datagram verdict cache.  On SBCL threads
;;;; share one heap and a mutex is all that is needed.  On modus they share nothing: a
;;;; worker's objects live in its own region, and the runtime REFUSES a store that would
;;;; let another thread reach one -- so a worker's first gated connect used to fail
;;;; outright, allowed or not, because recording it was a forbidden store.
;;;;
;;;; So on modus the bookkeeping has ONE OWNER, the thread that armed the gate, and a
;;;; worker SENDS what it would have written, over a MODUS:MAKE-CHANNEL -- bytes copied
;;;; into a shared ring and decoded fresh in the owner's heap, so nothing of the
;;;; worker's is ever stored anywhere shared.  What does not move is the DECISION: a
;;;; worker still decides synchronously, on its own thread, against the policy, which
;;;; it may read.  Only the record of it travels.
;;;;
;;;;   - The owner DRAINS the channel before it reads or writes the bookkeeping itself
;;;;     (CONNECTIONS, REPORT, NAMES-FOR, ...), so a reader sees every record sent
;;;;     before it asked.
;;;;   - A worker KEEPS the names it learned in a per-computation special as well, so
;;;;     its own next connect is decided against them before the owner has drained.
;;;;   - A worker does not cache datagram verdicts (that cache is the owner's); it
;;;;     decides each one, and remembers per computation which denials it has already
;;;;     reported, so a refused media stream is one message and not one per packet.
;;;;   - A send never blocks a connect.  A full channel drops the record and counts it
;;;;     in *GATE-DROPPED*, which REPORT prints.
;;;;
;;;; Everything here is #+modus-channel.  On SBCL the owner test is always true, every
;;;; path is the direct one, and nothing below is compiled.

(in-package #:cl-transport.gate)

(defvar *gate-owner* nil
  "The thread that armed the gate, and whose heap holds its record and names.  NIL until
   ARM; while NIL every thread is treated as the owner, which is the historical shape.")

(defvar *gate-channel* nil "The channel workers send their bookkeeping to, on modus.")

(defvar *gate-dropped* 0
  "Records a worker could not send because the channel was full.  A count rather than a
   wait: a connect is never held up by its own bookkeeping.")

(defvar *local-names* nil
  "On modus, this computation's own learned names: an alist of address-string -> names.")

(defvar *local-logged* nil
  "On modus, the datagram denials this computation has already sent to the owner.")

#+modus
(let ((register (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and register (fboundp register))
    (funcall register '*local-names*)
    (funcall register '*local-logged*)))

(defun %gate-owner-p ()
  "Is this thread the one that may write the gate's bookkeeping directly?"
  #-modus-channel t
  #+modus-channel (or (null *gate-owner*) (eq sb-thread:*current-thread* *gate-owner*)))

(defun %gate-adopt-owner ()
  "Make the calling thread the owner, and give it a channel, once.  Called by ARM."
  #+modus-channel
  (progn
    (unless *gate-owner* (setf *gate-owner* sb-thread:*current-thread*))
    (unless *gate-channel*
      (setf *gate-channel* (modus:make-channel :capacity 262144 :name "cl-transport gate"))))
  t)

(defun %gate-send (message)
  "Send MESSAGE, a list of plain data, to the owner.  Never waits."
  #+modus-channel
  (unless (and *gate-channel*
               (ignore-errors (modus:channel-send *gate-channel* message :timeout 0)))
    (incf *gate-dropped*))
  #-modus-channel
  (declare (ignore message))
  nil)

(defun %gate-drain ()
  "On the owner: apply everything workers have sent.  Elsewhere, and on SBCL, nothing."
  #+modus-channel
  (when (and *gate-channel* *gate-owner* (%gate-owner-p))
    (loop
      (multiple-value-bind (message ok) (modus:channel-try-receive *gate-channel*)
        (unless ok (return))
        (ignore-errors (%gate-apply message)))))
  nil)

(defun %gate-apply (message)
  (ecase (first message)
    (:connection (apply #'%note-connection (rest message)))
    (:name (%note-name-key (second message) (third message)))))
