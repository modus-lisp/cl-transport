;;;; src/loop.lisp -- one thread, many sockets: an event loop over cl-transport/sockets.
;;;;
;;;; A thread per job costs a thread per job.  On modus's bare-metal boards that is the whole
;;;; budget: twelve slots, all of them on core 0, so a WebRTC session's six threads bought no
;;;; parallelism and two sessions did not fit.  And every thread that blocks in a read is a
;;;; thread whose end has to be arranged -- the class of bug that kept a board's sessions alive
;;;; long after their sockets closed.  So the gateway runs here instead: one loop, callbacks.
;;;;
;;;; A LOOP holds three things:
;;;;   WATCHES  a socket (TCP-SOCKET, listener, or UDP-ENDPOINT) and a function called with it
;;;;            whenever it has input -- bytes buffered, a connection to accept, datagrams
;;;;            queued.  The function must not wait; it reads what is there and returns.
;;;;   TIMERS   a function to call at a time.  AFTER returns a handle CANCEL takes back.
;;;;   POSTED   functions to run on the loop's thread, soon -- the one entry point another
;;;;            thread may use (POST takes a lock; nothing else here does).
;;;;
;;;; Ending something is closing its sockets and cancelling its timers: no thread to join, no
;;;; read to wake.  UNWATCH is safe from inside a callback, including the callback's own.
;;;;
;;;; WAITING.  There is no portable multi-descriptor wait (sockets.lisp says the same), so an
;;;; idle loop checks every watched socket, then waits on ONE of them for at most 10 ms or
;;;; until the next timer.  On modus that wait is what pumps the network -- any socket's wait
;;;; runs NET-PUMP, which files arriving packets for every socket -- so a UDP or TCP arrival
;;;; is seen within the slice whichever socket the loop happened to wait on.  On SBCL the same
;;;; slice bounds how late a readiness on a socket the loop was not waiting on is noticed.
;;;;
;;;; ERRORS.  A callback that signals does not end the loop: the condition goes to the loop's
;;;; ERROR-HOOK (a function of (condition what), default: print it) and the loop goes on.  The
;;;; callback's owner decides whether that error ends its session; the loop cannot know.

(defpackage #:cl-transport.loop
  (:use #:cl #:cl-transport.sockets)
  (:export #:event-loop #:make-event-loop #:*event-loop*
           #:watch #:unwatch #:watching-p #:after #:every-seconds #:cancel #:post
           #:run-once #:run #:stop #:running-p #:loop-thread
           #:loop-error-hook #:loop-stats #:now-seconds))

(in-package #:cl-transport.loop)

(defvar *event-loop* nil "The loop the current code runs on, bound while it runs.")

(defun now-seconds ()
  "Monotonic seconds, as a double: the loop's clock."
  (/ (float (get-internal-real-time) 1d0) internal-time-units-per-second))

(defclass event-loop ()
  ((watches :initform '() :accessor %watches)        ; list of WATCH-RECs, newest first
   (timers :initform '() :accessor %timers)          ; TIMERs, soonest first
   (posted :initform '() :accessor %posted)          ; thunks, newest first (under LOCK)
   (lock :initform (sb-thread:make-mutex :name "event-loop post") :reader %lock)
   (stop :initform nil :accessor %stop)
   (thread :initform nil :accessor loop-thread)
   (error-hook :initarg :error-hook :accessor loop-error-hook
               :initform (lambda (c what)
                           (format *error-output* "~&[loop] ~a: ~a~%" what c)
                           (finish-output *error-output*)))
   ;; counters, for "is it alive and what is it doing" from a REPL
   (turns :initform 0 :accessor %turns)
   (callbacks :initform 0 :accessor %callbacks)
   (errors :initform 0 :accessor %errors)))

(defun make-event-loop (&rest initargs) (apply #'make-instance 'event-loop initargs))

(defclass watch-rec ()
  ((source :initarg :source :reader wr-source)
   (fn :initarg :fn :reader wr-fn)
   (what :initarg :what :reader wr-what)
   (live :initform t :accessor wr-live)))

(defclass timer ()
  ((due :initarg :due :accessor timer-due)
   (fn :initarg :fn :reader timer-fn)
   (what :initarg :what :reader timer-what)
   (interval :initarg :interval :initform nil :reader timer-interval)
   (live :initform t :accessor timer-live)))

;;; ---- registering -------------------------------------------------------------------------

(defun watch (loop source fn &key (what "watch"))
  "Call FN with SOURCE on LOOP's thread whenever SOURCE has input.  Returns SOURCE."
  (unwatch loop source)
  (push (make-instance 'watch-rec :source source :fn fn :what what) (%watches loop))
  source)

(defun unwatch (loop source)
  "Stop watching SOURCE.  Safe inside any callback: a record removed mid-turn is not called."
  (dolist (w (%watches loop))
    (when (eq (wr-source w) source) (setf (wr-live w) nil)))
  (setf (%watches loop) (remove source (%watches loop) :key #'wr-source))
  nil)

(defun watching-p (loop source) (and (find source (%watches loop) :key #'wr-source) t))

(defun %insert-timer (loop timer)
  (setf (%timers loop) (merge 'list (list timer) (%timers loop) #'< :key #'timer-due)))

(defun after (loop seconds fn &key (what "timer"))
  "Call FN (no arguments) on LOOP's thread SECONDS from now.  Returns a handle for CANCEL."
  (let ((timer (make-instance 'timer :due (+ (now-seconds) (max 0 seconds)) :fn fn :what what)))
    (%insert-timer loop timer)
    timer))

(defun every-seconds (loop seconds fn &key (what "periodic"))
  "Call FN every SECONDS until CANCELled.  The first call is SECONDS from now."
  (let ((timer (make-instance 'timer :due (+ (now-seconds) seconds) :fn fn :what what
                                     :interval seconds)))
    (%insert-timer loop timer)
    timer))

(defun cancel (loop timer)
  "Take back TIMER (NIL is fine).  Safe inside any callback, the timer's own included."
  (when timer
    (setf (timer-live timer) nil)
    (setf (%timers loop) (remove timer (%timers loop))))
  nil)

(defun post (loop fn)
  "Run FN on LOOP's thread, soon.  The one call another thread may make."
  (sb-thread:with-mutex ((%lock loop)) (push fn (%posted loop)))
  t)

(defun stop (loop) (post loop (lambda () (setf (%stop loop) t))))
(defun running-p (loop) (and (loop-thread loop) (not (%stop loop))))

;;; ---- turning -------------------------------------------------------------------------------

(defun %call (loop what fn &rest args)
  (incf (%callbacks loop))
  (handler-case (apply fn args)
    (serious-condition (c)
      (incf (%errors loop))
      (ignore-errors (funcall (loop-error-hook loop) c what)))))

(defun %ready-p (source)
  "Does SOURCE have input now?  Never waits (a zero wait still pumps the network on modus)."
  (handler-case
      (cond ((udp-endpoint-p source)
             (and (not (udp-closed-p source))
                  (or (plusp (udp-pump source :timeout-ms 0))
                      (udp-accept-pending-p source)
                      (%udp-queued-p source))))
            ((tcp-socket-p source)
             (and (not (tcp-closed-p source))
                  (or (tcp-buffered-p source)
                      (cl-transport.sockets::%readable-p source 0))))
            (t (cl-transport.sockets::%readable-p source 0)))
    (error () t)))   ; a broken socket is "ready": its read reports what happened

(defun %udp-queued-p (ep)
  (loop for peer being the hash-values of (cl-transport.sockets::udp-endpoint-peers ep)
        thereis (udp-peer-ready-p peer)))

(defun %run-posted (loop)
  (let ((thunks (sb-thread:with-mutex ((%lock loop))
                  (prog1 (reverse (%posted loop)) (setf (%posted loop) '())))))
    (dolist (fn thunks) (%call loop "posted" fn))
    (and thunks t)))

(defun %run-timers (loop)
  (let ((now (now-seconds)) (ran nil))
    (loop
      (let ((timer (first (%timers loop))))
        (unless (and timer (<= (timer-due timer) now)) (return))
        (pop (%timers loop))
        (when (timer-live timer)
          (setq ran t)
          (when (timer-interval timer)        ; re-arm before the call, so CANCEL inside it works
            (setf (timer-due timer) (+ now (timer-interval timer)))
            (%insert-timer loop timer))
          (%call loop (timer-what timer) (timer-fn timer)))))
    ran))

(defun %run-watches (loop)
  (let ((ran nil))
    ;; a snapshot: callbacks may WATCH and UNWATCH; a removed record is skipped by LIVE
    (dolist (w (reverse (%watches loop)))
      (when (and (wr-live w) (%ready-p (wr-source w)))
        (setq ran t)
        (%call loop (wr-what w) (wr-fn w) (wr-source w))))
    ran))

(defun %idle-wait (loop seconds)
  "Wait up to SECONDS for something to happen.  On modus any socket's wait pumps the network."
  (when (plusp seconds)
    (let ((source (find-if (lambda (s) (or (udp-endpoint-p s) (tcp-socket-p s)))
                           (%watches loop) :key #'wr-source)))
      (cond ((null source) (sleep seconds))
            ((udp-endpoint-p (wr-source source))
             (udp-pump (wr-source source) :timeout-ms (max 1 (round (* seconds 1000)))))
            (t (ignore-errors
                (cl-transport.sockets::%readable-p (wr-source source) seconds)))))))

(defun run-once (loop &key (max-wait 0.01))
  "One turn: posted functions, due timers, ready watches; if none of them did anything, wait
   up to MAX-WAIT seconds (less if a timer is due sooner).  T if anything ran."
  (let ((*event-loop* loop))
    (incf (%turns loop))
    (let ((ran (or (%run-posted loop) nil)))
      (when (%run-timers loop) (setq ran t))
      (when (%run-watches loop) (setq ran t))
      (unless ran
        (let* ((next (first (%timers loop)))
               (until (if next (- (timer-due next) (now-seconds)) max-wait)))
          (%idle-wait loop (max 0 (min max-wait until)))))
      ran)))

(defun run (loop)
  "Turn LOOP on this thread until STOP.  Returns when stopped."
  (setf (%stop loop) nil
        (loop-thread loop) sb-thread:*current-thread*)
  (unwind-protect
       (loop until (%stop loop) do (run-once loop))
    (setf (loop-thread loop) nil)))

(defun loop-stats (loop)
  (list :watches (length (%watches loop)) :timers (length (%timers loop))
        :turns (%turns loop) :callbacks (%callbacks loop) :errors (%errors loop)))
