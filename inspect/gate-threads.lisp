;;;; gate-threads.lisp — the gate armed, with connections made from worker threads.
;;;;
;;;;   sbcl --script inspect/gate-threads.lisp
;;;;   modus --script inspect/gate-threads.lisp
;;;;
;;;; On SBCL every thread writes the gate's record directly.  On modus threads share no
;;;; state, so a worker SENDS its bookkeeping to the thread that armed the gate, over a
;;;; channel (gate-channel.lisp) -- before which a worker's first gated connect failed
;;;; outright.  The same checks hold on both: every worker's connections are decided on
;;;; its own thread, recorded exactly once against its own name, a name a worker learned
;;;; decides its own next connect, and a stream of denied datagrams is one record.

(require :asdf)
(require :sb-bsd-sockets)
(push (make-pathname :name nil :type nil
                     :defaults (merge-pathnames "../" (make-pathname :name nil :type nil :defaults *load-truename*)))
      asdf:*central-registry*)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-transport")))

(defpackage #:gate-threads-test (:use #:cl)) (in-package #:gate-threads-test)

(defvar *pass* 0) (defvar *fail* 0)
(defun ok (name got expect)
  (if (equal got expect)
      (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a~%       got    ~s~%       expect ~s~%" name got expect))))

(defparameter +workers+ 8)
(defparameter +datagrams+ 50)

(defun try-connect (address)
  "What a connect to ADDRESS:9 ends in, as a keyword."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case (progn (sb-bsd-sockets:socket-connect s address 9) :connected)
           (cl-transport.gate:blocked () :blocked)
           (error () :refused))                ; refused by the network, not the gate
      (ignore-errors (sb-bsd-sockets:socket-close s)))))

(defun try-datagrams (address n)
  "Send N datagrams to ADDRESS:9; how many the gate blocked."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
        (buf (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
        (blocked 0))
    (unwind-protect
         (dotimes (i n blocked)
           (handler-case (sb-bsd-sockets:socket-send s buf 4 :address (list address 9))
             (cl-transport.gate:blocked () (incf blocked))
             (error () nil)))
      (ignore-errors (sb-bsd-sockets:socket-close s)))))

(defun worker ()
  ;; Learned on THIS thread: on modus it is decided against before the owner has
  ;; drained the channel, from this computation's own copy.
  (cl-transport.gate::note-name #(127 0 0 2) "denied.test")
  (list (try-connect #(127 0 0 2))           ; denied by name
        (try-connect #(127 0 0 3))           ; allowed: refused by the network
        (try-datagrams #(127 0 0 4) +datagrams+)))

(format t "~&== the gate, with workers~%")
(setf cl-transport.gate:*allow-loopback* nil
      cl-transport.gate:*default-action* :allow)
(cl-transport.gate:clear-policy)
(cl-transport.gate:add-rule :deny "*" "denied.test" "*" "test")
(cl-transport.gate:add-rule :deny "*" "127.0.0.4" "*" "test")
(cl-transport.gate:arm)
(cl-transport.gate:clear-connections)

(let* ((threads (loop for i below +workers+
                      collect (sb-thread:make-thread #'worker :name (format nil "worker-~d" i))))
       (results (mapcar (lambda (th) (sb-thread:join-thread th :default :died)) threads)))
  (ok "every worker finished" (count :died results) 0)
  (ok "a name a worker learned decides its own next connect"
      (count-if (lambda (r) (and (consp r) (eq (first r) :blocked))) results) +workers+)
  (ok "an allowed connect from a worker goes through the gate (refused by the network)"
      (count-if (lambda (r) (and (consp r) (eq (second r) :refused))) results) +workers+)
  (ok "every denied datagram from a worker is refused"
      (reduce #'+ (mapcar (lambda (r) (if (consp r) (third r) 0)) results)) (* +workers+ +datagrams+))

  (let* ((cs (cl-transport.gate:connections :limit nil))
         (who (lambda (c) (cl-transport.gate:connection-principal c))))
    (ok "each worker's two connections and one datagram stream are recorded, once each"
        (length cs) (* 3 +workers+))
    (ok "every record names the worker that made it"
        (sort (remove-duplicates (mapcar who cs) :test #'string=) #'string<)
        (sort (loop for i below +workers+ collect (format nil "worker-~d" i)) #'string<))
    (ok "the denials name their rule"
        (count-if (lambda (c) (equal (getf (cl-transport.gate:connection-plist c) :source) "test"))
                  cs)
        (* 2 +workers+))
    (ok "the name a worker learned reaches the shared table"
        (cl-transport.gate::names-for "127.0.0.2") '("denied.test"))
    (ok "nothing was dropped" cl-transport.gate::*gate-dropped* 0)))

(cl-transport.gate:disarm)
(format t "~&~d passed, ~d failed~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
