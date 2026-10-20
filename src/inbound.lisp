;;;; src/inbound.lisp — one EXPOSE for inbound reachability, symmetric to DIAL.
;;;;
;;;; EXPOSE on-connection :backend X ...  ->  closer-thunk
;;;;
;;;; The mirror image of DIAL: where DIAL opens ONE outbound stream, EXPOSE arranges
;;;; inbound reachability through a backend and delivers EACH inbound connection to
;;;; ON-CONNECTION, called as (funcall on-connection stream peer-plist).  Callers get a
;;;; uniform "hand me each inbound stream" and never branch on how reachability happens.
;;;;
;;;;   :tcp   a plain local listener (sb-bsd-sockets accept loop) — built in
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

(defun %peer-plist (sock)
  "The peer's address and port as the plist an on-connection callback gets, or NIL
   fields where the kernel will not say."
  (multiple-value-bind (address port) (ignore-errors (sb-bsd-sockets:socket-peername sock))
    (list :host (and address (format nil "~{~d~^.~}" (coerce address 'list)))
          :port port)))

(defun %tcp-listen (on-connection opts)
  "Built-in :TCP inbound: bind a local listener and hand each accepted connection to
   ON-CONNECTION on its own thread.  On sb-bsd-sockets and sb-thread, so an inbound
   listener needs nothing beyond SBCL."
  (destructuring-bind (&key (host "0.0.0.0") port &allow-other-keys) opts
    (unless port (error "cl-transport: :tcp expose needs :port"))
    (let* ((server (cl-transport.listeners:tcp-listen port :address host))
           (stop nil))
      (labels ((serve (sock)
                 (sb-thread:make-thread
                  (lambda ()
                    (unwind-protect
                         (funcall on-connection
                                  (sb-bsd-sockets:socket-make-stream
                                   sock :input t :output t :element-type '(unsigned-byte 8)
                                        :buffering :full)
                                  (%peer-plist sock))
                      (ignore-errors (sb-bsd-sockets:socket-close sock))))
                  :name "cl-transport-tcp-conn"))
               (accept-loop ()
                 (loop until stop do
                   (handler-case
                       (serve (sb-bsd-sockets:socket-accept server))
                     (error () (unless stop (sleep 0.05)))))))
        (let ((thread (sb-thread:make-thread #'accept-loop :name "cl-transport-tcp-accept")))
          (lambda ()
            (setf stop t)
            (ignore-errors (sb-bsd-sockets:socket-close server))
            (ignore-errors (sb-thread:terminate-thread thread))))))))
