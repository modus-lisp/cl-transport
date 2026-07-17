;;;; src/inbound.lisp — one EXPOSE for inbound reachability, symmetric to DIAL.
;;;;
;;;; EXPOSE on-connection :backend X ...  ->  closer-thunk
;;;;
;;;; The mirror image of DIAL: where DIAL opens ONE outbound stream, EXPOSE arranges
;;;; inbound reachability through a backend and delivers EACH inbound connection to
;;;; ON-CONNECTION, called as (funcall on-connection stream peer-plist).  Callers get a
;;;; uniform "hand me each inbound stream" and never branch on how reachability happens.
;;;;
;;;;   :tcp   a plain local listener (usocket accept loop)     — built in
;;;;   <other> a pluggable inbound backend (REGISTER-LISTENER) — e.g. :frp via cl-frpc,
;;;;           which gives a NAT'd host a public endpoint through an frp relay.
;;;;
;;;; A backend fn takes (on-connection opts-plist) and returns a zero-arg closer thunk.

(in-package #:cl-transport)

(defvar *listeners* (make-hash-table :test 'eq)
  "Pluggable inbound backends: keyword -> (lambda (on-connection opts) -> closer).")

(defun register-listener (name fn)
  "Register FN as the inbound backend for NAME.  FN takes (on-connection opts-plist)
   and returns a zero-arg closer thunk; it must call (on-connection stream peer) for
   each inbound connection.  A provider system (e.g. cl-frpc for :FRP) calls this at
   load time — nothing backend-specific lives in this system."
  (check-type name keyword)
  (setf (gethash name *listeners*) fn)
  name)

(defun listener-available-p (name)
  "True if EXPOSE can service inbound backend NAME (built-in :TCP or a loaded provider)."
  (or (eq name :tcp) (and (gethash name *listeners*) t)))

(defun expose (on-connection &rest opts &key (backend :tcp) &allow-other-keys)
  "Arrange inbound reachability via BACKEND and deliver each inbound connection to
   ON-CONNECTION, called as (funcall on-connection stream peer-plist).  Returns a
   zero-arg closer thunk that stops accepting and tears everything down.  OPTS are
   backend-specific:
     :tcp    -> :host (default \"0.0.0.0\") :port (required)
     :frp    -> see cl-frpc (:server :port :token :proxy-type :remote-port ...)
   Signals if BACKEND has no registered provider."
  (check-type on-connection function)
  (let ((opts (copy-list opts)))
    (remf opts :backend)
    (if (eq backend :tcp)
        (%tcp-listen on-connection opts)
        (let ((fn (gethash backend *listeners*)))
          (if fn
              (funcall fn on-connection opts)
              (error "cl-transport: no inbound backend registered for ~s — load its ~
                      provider first (e.g. the cl-frpc system for :frp)." backend))))))

(defun %tcp-listen (on-connection opts)
  "Built-in :TCP inbound: bind a local listener and hand each accepted connection to
   ON-CONNECTION on its own thread."
  (destructuring-bind (&key (host "0.0.0.0") port &allow-other-keys) opts
    (unless port (error "cl-transport: :tcp expose needs :port"))
    (let* ((server (usocket:socket-listen host port :element-type '(unsigned-byte 8)
                                                     :reuse-address t))
           (stop nil))
      (labels ((serve (sock)
                 (bt:make-thread
                  (lambda ()
                    (unwind-protect
                         (funcall on-connection (usocket:socket-stream sock)
                                  (list :host (ignore-errors (usocket:get-peer-address sock))
                                        :port (ignore-errors (usocket:get-peer-port sock))))
                      (ignore-errors (usocket:socket-close sock))))
                  :name "cl-transport-tcp-conn"))
               (accept-loop ()
                 (loop until stop do
                   (handler-case
                       (serve (usocket:socket-accept server :element-type '(unsigned-byte 8)))
                     (error () (unless stop (sleep 0.05)))))))
        (let ((thread (bt:make-thread #'accept-loop :name "cl-transport-tcp-accept")))
          (lambda ()
            (setf stop t)
            (ignore-errors (usocket:socket-close server))
            (ignore-errors (bt:destroy-thread thread))))))))
